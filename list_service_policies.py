#!/usr/bin/python

import boto3
import yaml
import json
import sys
import os



# get policies
org_client = boto3.client('organizations')
response = org_client.list_policies( Filter='SERVICE_CONTROL_POLICY' )
#print response['Policies']

for policy in response['Policies']:
    print "Name:\t%s\nDesc:\t%s\nId:\t%s\n" % (policy['Name'], policy['Description'], policy['Id'])


