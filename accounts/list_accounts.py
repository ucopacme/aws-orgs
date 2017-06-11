#!/usr/bin/python

import boto3

client = boto3.client('organizations')
response = client.list_accounts()
#print(response)
for account in response['Accounts']:
    print account['Name']
    print account['Arn']

