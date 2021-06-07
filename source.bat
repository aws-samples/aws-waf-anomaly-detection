@echo off
rem
rem Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
rem SPDX-License-Identifier: MIT-0
rem
rem Permission is hereby granted, free of charge, to any person obtaining a copy of this
rem software and associated documentation files (the "Software"), to deal in the Software
rem without restriction, including without limitation the rights to use, copy, modify,
rem merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
rem permit persons to whom the Software is furnished to do so.
rem
rem THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
rem INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
rem PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
rem HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
rem OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
rem SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
rem
rem The sole purpose of this script is to make the command
rem
rem     source .venv/bin/activate
rem
rem (which activates a Python virtualenv on Linux or Mac OS X) work on Windows.
rem On Windows, this command just runs this batch file (the argument is ignored).
rem
rem Now we don't need to document a Windows command for activating a virtualenv.

echo Executing .venv\Scripts\activate.bat for you
.venv\Scripts\activate.bat
