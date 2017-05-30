#!/usr/bin/python

import boto3
import yaml
import json
import sys
import os

# read yaml file describing Organiztion OU layout
if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
    policy_spec = yaml.load(open(sys.argv[1]).read())
print policy_spec


# determine the Root ID
org_client = boto3.client('organizations')
root_id = org_client.list_roots()['Roots'][0]['Id']
#print root_id

for policy in policy_spec['org']['policies']:

    content = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "%s",
            "Action": %s,
            "Resource": "*"
        }
    ]
}""" % (policy['Effect'], json.dumps(policy['Actions']))

    print content

    response = org_client.create_policy(
        Content=content,
        Description=policy['Desc'],
        Name=policy['Name'],
        Type='SERVICE_CONTROL_POLICY'
    )
    print response


