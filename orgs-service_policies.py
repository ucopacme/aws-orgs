#!/usr/bin/python

import boto3
import yaml
import json
import sys
import os


#
# functions
#
def create_policy_content ( my_policy ):
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (my_policy['Effect'], json.dumps(my_policy['Actions']))

def get_policy_content( policy_id ):
    response = org_client.describe_policy( PolicyId=policy_id )['Policy']['Content']
    return response

def delete_policy( policy_id ):
    response = org_client.delete_policy( PolicyId=policy_id )
    #print response

def create_policy( my_policy ):
    response = org_client.create_policy(
        Content=create_policy_content(my_policy),
        Description=my_policy['Description'],
        Name=my_policy['Name'],
        Type='SERVICE_CONTROL_POLICY'
    )
    #print response

def update_policy( my_policy, policy_id ):
    response = org_client.update_policy(
        PolicyId=policy_id,
        Content=create_policy_content(my_policy),
        Description=my_policy['Description'],
    )
    #print response

def print_existing_policies():
    print
    print "Provissioned Service Control Policies:"
    print
    response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
    for policy in response:
        print "Name:\t\t%s\nDescription:\t%s\nId:\t\t%s" % (policy['Name'], policy['Description'], policy['Id'])
        print "Content:\t%s\n" % get_policy_content(policy['Id'])




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
            'Description': policy['Description'],
            'Content': get_policy_content(policy['Id']) 
        }
        #print existing[policy['Name']]['Content']


# walk though policy_spec and make stuff happen
for policy in policy_spec['org']['policies']:
    if policy['Ensure'] == 'absent' and policy['Name'] in existing.keys():
        print "deleting policy: %s %s" % (policy['Name'], existing[policy['Name']]['Id'])
        delete_policy(existing[policy['Name']]['Id'])
    elif policy['Ensure'] != 'absent':
        if policy['Name'] not in existing.keys():
            print "creating policy: %s" % (policy['Name'])
            create_policy(policy)
        elif policy['Description'] != existing[policy['Name']]['Description'] or create_policy_content(policy) != existing[policy['Name']]['Content']:
            print "updating policy: %s" % (policy['Name'])
            update_policy(policy,existing[policy['Name']]['Id'])



# show results
print_existing_policies()

