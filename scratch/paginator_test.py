#!/usr/bin/python
import sys
import boto3

# client = boto3.client('iam')
# paginator = client.get_paginator('list_policies')
# 
# response_iterator = paginator.paginate(
#     Scope='AWS',
#     PaginationConfig={
#         'PageSize': 50,
#         #'StartingToken': 'string'
#     }
# )
# 
# print type(list(response_iterator)[0])
# print len(list(response_iterator))
# #print response_iterator.build_full_result()
# #print response_iterator['IsTruncated']

iam = boto3.client("iam")
aws_policies = []
marker = None
while True:
    if marker:
        response_iterator = iam.list_policies(
            Scope='AWS',
            MaxItems=200,
            Marker=marker
        )
    else:
        response_iterator = iam.list_policies(
            Scope='AWS',
            MaxItems=200
        )
    #print("Next Page : {} ".format(response_iterator['IsTruncated']))
    aws_policies += response_iterator['Policies'] 
    #for policy in response_iterator['Policies']:
    #    print(policy['PolicyName'])

    try:
        marker = response_iterator['Marker']
        #print(marker)
    except KeyError:
        #sys.exit()
        break

print len(aws_policies)
other_aws_policies = iam.list_policies(Scope='AWS', MaxItems=500)['Policies']
print len(other_aws_policies)

