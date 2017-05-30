#!/usr/bin/python
#
# Manage Organizaion OUs

import boto3
import yaml
import sys
import os

# read yaml file describing Organiztion OU layout
if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
    org_spec = yaml.load(open(sys.argv[1]).read())
#print org_spec


# determine the Root ID
org_client = boto3.client('organizations')
root_id = org_client.list_roots()['Roots'][0]['Id']
#print root_id

#current_ou = org_client.list_organizational_units_for_parent(ParentId=root_id)
#print current_ou['OrganizationalUnits']
#print


#
# function is_child
#
def is_child(ou):
    if 'OU' in ou and ou['OU'] != None and len(ou['OU']) != 0:
        return True
    else:
        return False

#
# function print_existing_ou 
#
def print_existing_ou (parent_name, parent_id, indent):
    # query aws for child orgs
    child_ou_list = org_client.list_organizational_units_for_parent(ParentId=parent_id)['OrganizationalUnits']

    # print parent ou name
    tab = '  '
    if len(child_ou_list ) >0:
        print tab*indent + parent_name + ':'
    else:
        print tab*indent + parent_name

    # check for child ou
    indent+=1
    for ou in child_ou_list:
        print_existing_ou (ou['Name'], ou['Id'], indent)



#
# function print_specified_ou 
#
def print_specified_ou (parent_name, child_ou_list, indent):
    tab = '  '
    print tab*indent + parent_name + ':'
    indent+=1

    for ou in child_ou_list:
        if is_child(ou):
            print_specified_ou (ou['Name'], ou['OU'], indent)
        else:
            print tab*indent + ou['Name']


#
# function create_specified_ou 
#
def create_specified_ou (specified_ou_list, parent_id):
    # query aws for child orgs
    existing_ou_list = org_client.list_organizational_units_for_parent(ParentId=parent_id)['OrganizationalUnits']

    for spec_ou in specified_ou_list:
        # check if this ou exists
        found = None
        for existing_ou in existing_ou_list:
            if spec_ou['Name'] == existing_ou['Name']:
                found = True
                found_ou_id = existing_ou['Id']
        if found:
            # test for child ou
            if is_child(spec_ou):
                create_specified_ou (spec_ou['OU'], found_ou_id)
        elif not found:
            # create it new ou
            print 'creating New ou', spec_ou['Name'], 'under parent Id', parent_id
            new_ou = org_client.create_organizational_unit(
                ParentId=parent_id,
                Name=spec_ou['Name']
            )
            # test for child ou
            if is_child(spec_ou) and \
                    isinstance(new_ou, dict) and \
                    'Id' in new_ou['OrganizationalUnit']:
                create_specified_ou (spec_ou['OU'], new_ou['OrganizationalUnit']['Id'])




print 'Existing org:'
print_existing_ou ('root', root_id, 0)
print
print 'Specified org:'
print_specified_ou (org_spec['Org']['Name'], org_spec['Org']['OU'], 0)
print
create_specified_ou (org_spec['Org']['OU'], root_id)
#print_existing_ou ('root', root_id, 0)



#######################################################################

# def get_ou_name(ou):
#     return ou['Name']
