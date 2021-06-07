#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# For consistency with other languages, `cdk` is the preferred import name for
# the CDK's core module.  The following line also imports it as `core` for use
# with examples from the CDK Developer's Guide, which are in the process of
# being updated to use `cdk`.  You may delete this import if you don't need it.
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_wafv2 as waf
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import core as cdk


class WafLookoutStack(cdk.Stack):

    # Number of minutes between each evaluation of ML
    anomalyDetectionRate = 5

    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Creating an API Gateway to demonstrate the solution
        api = apigateway.RestApi(self, "APIForWAFDemo",
                  rest_api_name="APIGW For WAF Demo",
                  description="This is a demo API Gateway.")

        mockIntegration = apigateway.MockIntegration( 
            passthrough_behavior= apigateway.PassthroughBehavior.WHEN_NO_TEMPLATES,
            request_templates = {"application/json": '{ "statusCode": 200 }'},
            integration_responses= [
                {
                    "statusCode": '200',
                    "responseTemplates": {
                        'application/json':"{ 'statusCode': '200' }"
                    }
                }
            ]
        )

        api.root.add_method("GET", mockIntegration, 
            method_responses=[{"statusCode": '200'}]
        )

        # Creating an AWS WAF Web Access Control List to deploy the AWS Managed rules
        # AWS WAF is not natively integrated with AWS CDK but could be created and managed through Cfn Methods
        web_acl=waf.CfnWebACL(self, "WAF ACL",
            name="WebACLForWAFDemo",
            default_action={ "allow": {} },
            scope="REGIONAL",
            visibility_config={
                "sampledRequestsEnabled": True,
                "cloudWatchMetricsEnabled": True,
                "metricName": "web-acl",
            },
            rules=[
                {
                    "priority": 1,
                    "overrideAction": { "none": {} },
                    "visibilityConfig": {
                        "sampledRequestsEnabled": True,
                        "cloudWatchMetricsEnabled": True,
                        "metricName": "AWS-AWSManagedRulesCommonRuleSet",
                    },
                    "name": "AWS-AWSManagedRulesCommonRuleSet",
                    "statement": {
                        "managedRuleGroupStatement": {
                            "vendorName": "AWS",
                            "name": "AWSManagedRulesCommonRuleSet",
                        },
                    },
                }
            ]
        )
    
        # Associating WAS WAF ACL to API GW deployment
        waf.CfnWebACLAssociation(self, "WAF Assoc",
            resource_arn="arn:aws:apigateway:" + self.region + "::/restapis/" + api.rest_api_id + "/stages/prod",
            web_acl_arn=web_acl.attr_arn
        )

        # Creating a Lambda function that will forward the anomaly to SecurityHub
        detectionHandler = lambda_.Function(self, "DetectHandler",
                    runtime=lambda_.Runtime.PYTHON_3_7,
                    code=lambda_.Code.from_asset("lookout_alarm"),
                    handler="detect.lambda_handler"
        )

        detectionHandler.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=['securityhub:BatchImportFindings' ],
            resources=['arn:aws:securityhub:*:*:product/*/default']
        ))

        # Create an IAM role for Lookout for Metrics
        lookoutServiceRole = iam.Role(self, 'LookoutExecutionRole', 
            assumed_by= iam.ServicePrincipal('lookoutmetrics.amazonaws.com')
        )

        lookoutServiceRole.add_to_policy(
            iam.PolicyStatement(
                effect= iam.Effect.ALLOW,
                resources= ['*'],
                actions= [            
                    'cloudwatch:ListMetrics',
                    'cloudwatch:GetMetricData',
                    'lambda:invoke*'
                ]
            )
        )

        # Create a Lookout for Metrics Detector
        detector = cdk.CfnResource(self, "WAFBlockingRequestDetector",
            type="AWS::LookoutMetrics::AnomalyDetector",
            properties= {
                "AnomalyDetectorConfig":{ 
                    "AnomalyDetectorFrequency": "PT" + str(self.anomalyDetectionRate) + "M"
                },
                "AnomalyDetectorDescription": "A simple detector over WAF blocking rules",
                "AnomalyDetectorName": "WAFBlockingRequestDetector",
                "MetricSetList": [{
                    "DimensionList" : [ "Region", "Rule", "WebACL" ],
                    "MetricList" : [ {
                        "AggregationFunction" : "SUM",
                        "MetricName" : "BlockedRequests",
                        "Namespace" : "AWS/WAFV2"
                    } ],
                    "MetricSetName" : "WAFBlockingDetector",
                    "MetricSource" : {
                        "CloudwatchConfig":  {
                            "RoleArn" : lookoutServiceRole.role_arn
                        }
                    }
                }]
            }
        )

        cdk.CfnResource(self, "WAFBlockingRequestDetectorAlert",
            type = "AWS::LookoutMetrics::Alert",
            properties= {
                "Action": {
                    "LambdaConfiguration" : {
                        "LambdaArn" : detectionHandler.function_arn,
                        "RoleArn" : lookoutServiceRole.role_arn
                    },
                },
                "AlertDescription": "Amazon Lookout for Metrics has detected an anomaly on AWS WAF BlockedRequests",
                "AlertName": "AWS_WAF_BlockedRequests_Anomaly_Detection",
                "AlertSensitivityThreshold": 10,
                "AnomalyDetectorArn": detector.get_att("Arn")
            }
        )

        # Creating a simple Lambda Handler to publish the zero values for AWS WAF metrics
        zeroLambda = lambda_.Function(self, "CWLZeroValue",
                    runtime=lambda_.Runtime.PYTHON_3_7,
                    code=lambda_.Code.from_asset("cloudwatch_zero"),
                    handler="handler.lambda_handler"
        )

        zeroLambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=['cloudwatch:PutMetricData' ],
            resources=['*'],
            conditions={
                "StringEquals": {
                    "cloudwatch:namespace": "AWS/WAFV2"
                }
            }
        ))


        # And schedule it every 5 minutes
        events.Rule(self, 'ScheduledZeroValue', 
            schedule= events.Schedule.rate(cdk.Duration.minutes(self.anomalyDetectionRate)),
            targets= [ targets.LambdaFunction(zeroLambda, event= events.RuleTargetInput.from_object({
                'WebACLId': 'WebACLForWAFDemo', 
                'RuleId': 'AWS-AWSManagedRulesCommonRuleSet'
            })) ]
        )
