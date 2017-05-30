#!/usr/bin/python
#
# Manage Organizaion OUs

import boto3
import yaml
import sys
import os

# read yaml file describing Organiztion OU layout
if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
    ou_layout = yaml.load(open(sys.argv[1]).read())

#print ou_layout

# determine the Root ID
org_client = boto3.client('organizations')
root_id = org_client.list_roots()['Roots'][0]['Id']
#print root_id

current_ou = org_client.list_organizational_units_for_parent(ParentId=root_id)
#print current_ou['OrganizationalUnits']

current_ou_list = []
for ou in current_ou['OrganizationalUnits']:
    current_ou_list.append(ou['Name'])

print current_ou_list
print ou_layout['Root']['OU']
print

# def build_ou (existing, desired):
#     for ou in desired:
#         if isinstance(ou, str):
#             if ou not in existing:
#                 print "creating OU: " + ou
#                 #response = org_client.create_organizational_unit(
#                 #    ParentId=root_id,
#                 #    Name=ou
#                 #)
#         else if type(ou) is dict:
#             build_ou (
# 
# 
# 
#             if ou not in existing:
#                 print "creating OU: " + ou
#                 #response = org_client.create_organizational_unit(
#                 #    ParentId=root_id,
#                 #    Name=ou
#                 #)

def build_ou (desired):
    for ou in desired:
        print ou
        # check if this ou exists
        if ou['Name'] not in current_ou_list:
            print "creating OU: " + ou['Name']
        # check if ou has child ou
        if defined(ou['OU']) and ou['OU'] != None:
            print "decending into " + ou['Name']
            build_ou (ou['OU'])

        #if isinstance(ou, str):
        #    print ou
        #elif isinstance(ou, list):
        #    build_ou (ou)
        #elif isinstance(ou, dict):
        #    print ou.values()
        #else:
        #    print type(ou)

build_ou (ou_layout['Root']['OU'])
