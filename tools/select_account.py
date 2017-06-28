#!/usr/bin/python
#
# generate STS credentials 

"""Tools for basic AWS session setup.

Usage:
  assume_role.py (-h | --help)
  assume_role.py --version
  assume_role.py [--mfa-token <token>] [--profile <profile>]

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -m, --mfa-token <token>    6 digit tokencode provided by MFA device.

"""


import boto3
from docopt import docopt

args = docopt(__doc__)
session = boto3.Session(profile_name=args['--profile'])

# get list of all account in this organization
org_client = session.client('organizations')
account_list = org_client.list_accounts()['Accounts']

# get Id of root account
root_account = org_client.list_roots()['Roots'][0]['Arn']
root_account_ID = root_account.split(':')[4]

# create local hash of account names and IDs. Do not include root account
account_hash = {}
for account in account_list:
     #print account['Id']
     #print account['Name']
     if account['Id'] != root_account_ID:
         account_hash[account['Name']] = {
             'Id': account['Id']
         }
 
# make sorted array of account names
account_names = account_hash.keys()
account_names.sort()

# ask user what account she wants to assume a role into
i = 0
for name in account_names:
    print '[' + str(i) + ']' + name
    i = i+1
index = raw_input("enter the number of the account you want to use: ")
account_id = account_hash[account_names[int(index)]]['Id']

# create credentials for the assumed role
role_name = 'OrganizationAccountAccessRole'
role_arn = 'arn:aws:iam::' + account_id + ':role/' + role_name
role_session_name = account_id + '-' + role_name
#print role_arn
#print role_session_name
sts_client = session.client('sts')
assumedRoleObject = sts_client.assume_role(
    RoleArn=role_arn,
    RoleSessionName=role_session_name
)
credentials = assumedRoleObject['Credentials']
role_user = assumedRoleObject['AssumedRoleUser']
#print credentials
#print role_user['Arn']

print "export AWS_ACCESS_KEY_ID=%s" % credentials['AccessKeyId']
print "export AWS_SECRET_ACCESS_KEY=%s" % credentials['SecretAccessKey']
print "export AWS_SECURITY_TOKEN=%s" % credentials['SessionToken']
print "export AWS_SECURITY_TOKEN_EXPIRATION='%s'" % credentials['Expiration']




# Things you can now do:

#s3_local_client = boto3.client(
#    's3',
#)
#s3_assume_role_client = boto3.client(
#    's3',
#    aws_access_key_id = credentials['AccessKeyId'],
#    aws_secret_access_key = credentials['SecretAccessKey'],
#    aws_session_token = credentials['SessionToken'],
#)
#bucket_list = s3_local_client.list_buckets()
#print bucket_list
#bucket_list = s3_assume_role_client.list_buckets()
#print bucket_list

# iam_assume_role_client = boto3.client(
#     'iam',
#     aws_access_key_id = credentials['AccessKeyId'],
#     aws_secret_access_key = credentials['SecretAccessKey'],
#     aws_session_token = credentials['SessionToken'],
# )
# 
# response = iam_assume_role_client.list_roles() 
# print response['Roles']


