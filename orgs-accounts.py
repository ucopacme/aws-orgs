#!/usr/bin/python

import boto3

org_client = boto3.client('organizations')
account_lookup = {}
for account in org_client.list_accounts()['Accounts']:
    #print account
    print account['Name']
    print account['Id']
    print account['Email']
    print
    #print org_client.describe_account(AccountId=account['Id'])['Account']
    account_lookup[account['Name']] = account['Id']
print account_lookup
