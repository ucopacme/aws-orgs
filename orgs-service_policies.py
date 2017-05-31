#!/usr/bin/python

import boto3
import yaml
import json
import sys
import os


#
# functions
#
def get_policy_statement ( effect, actions ):
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (effect, json.dumps(actions))

def delete_policy( id ):
    response = org_client.delete_policy( PolicyId=id )
    #print response

def create_policy( policy ):
    response = org_client.create_policy(
        Content=get_policy_statement(policy['Effect'], policy['Actions']),
        Description=policy['Desc'],
        Name=policy['Name'],
        Type='SERVICE_CONTROL_POLICY'
    )
    #print response

def print_existing_policies():
    print
    print "Provissioned Service Control Policies:"
    print
    response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
    for policy in response:
        print "Name:\t%s\nDesc:\t%s\nId:\t%s\n" % (policy['Name'], policy['Description'], policy['Id'])




# read input yaml file with policy specs for this organization
if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
    policy_spec = yaml.load(open(sys.argv[1]).read())
    #print policy_spec

# setup orgs client
org_client = boto3.client('organizations')


# create reference hash of existing policies indexed by name
existing = {}
response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
for policy in response:
    if policy['Name'] != 'FullAWSAccess':
        existing[policy['Name']] = {
            'Id': policy['Id'],
            'Desc': policy['Description']
        }


# walk though policy_spec and make stuff happen
for policy in policy_spec['org']['policies']:
    if policy['Ensure'] == 'Absent' and policy['Name'] in existing.keys():
        print "deleting policy: %s %s" % (policy['Name'], existing[policy['Name']]['Id'])
        delete_policy(existing[policy['Name']]['Id'])
    elif policy['Name'] not in existing.keys():
        print "creating policy: %s" % (policy['Name'])
        create_policy(policy)


# show results
print_existing_policies()

