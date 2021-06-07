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

import boto3
import datetime
import os
import uuid

securityHub = boto3.client('securityhub')
sts         = boto3.client('sts')
accountId   = sts.get_caller_identity()['Account']

def lambda_handler(event, context):
    # I create a datetime object with timezone
    my_date = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

    # I generate an UUID as my fndingId
    findingId = str(uuid.uuid4())

    # submit the finding to Security Hub
    result = securityHub.batch_import_findings(Findings = [
        {
            'SchemaVersion': '2018-10-08',
            'Id': findingId,
            'ProductArn': "arn:aws:securityhub:"+ os.environ['AWS_REGION'] +":" + accountId +":product/" + accountId +"/default",
            'AwsAccountId': accountId,
            'GeneratorId': 'LookoutForMetrics',
            'Types': [ 'AWS WAF Anomaly' ],
            'CreatedAt': my_date.isoformat(),
            'UpdatedAt': my_date.isoformat(),
            'Severity': {
                'Product': 1,
                'Normalized': 10
            },
            'Title': event['alertName'],
            'Description': 'Anomaly detected [' + event['alertDescription'] + '] with a score of ' + str(event['anomalyScore']),
            'ProductFields': { 'Product Name': 'AWS WAF/Lookout For Metrics' },
            'Resources': [{
                'Type': 'Account',
                'Id': accountId,
                'Partition': 'aws',
                'Region': os.environ['AWS_REGION'],
            }],
            'Remediation': {
                'Recommendation': {
                  'Text': 'Navigate in Lookout for Metrics to see more information on this anomaly',
                  'Url': 'https://' + os.environ['AWS_REGION'] + '.console.aws.amazon.com/lookoutmetrics/home#' + event['anomalyDetectorArn'] + '/anomalies/anomaly' + event['alertEventId'][event['alertEventId'].rindex('/'):]
                }
            },
            'RecordState': 'ACTIVE'
        }
    ])

    # print results
    print(result)
