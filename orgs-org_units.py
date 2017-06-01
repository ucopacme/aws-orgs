#!/usr/bin/python
#
# Manage Organizaion OUs

import boto3
import yaml
import sys
import os

# read yaml file describing Organiztion OU layout
if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
    yaml_file = open(sys.argv[1]).read()
    org_spec = yaml.load(yaml_file)
#print yaml.dump(org_spec)

# determine the Root ID
org_client = boto3.client('organizations')
root_id = org_client.list_roots()['Roots'][0]['Id']
#print root_id

# enable policy type in root
policy_types = org_client.describe_organization()['Organization']['AvailablePolicyTypes']
for p_type in policy_types:
    if p_type['Type'] == 'SERVICE_CONTROL_POLICY' and p_type['Status'] != 'ENABLED':
        response = org_client.enable_policy_type(
            RootId=root_id,
            PolicyType='SERVICE_CONTROL_POLICY'
        )



#
# function is_child
#
def is_child(ou):
    if 'OU' in ou and ou['OU'] != None and len(ou['OU']) != 0:
        return True
    else:
        return False


#
# function ensure_absent
#
def ensure_absent(ou):
    if 'Ensure' in ou and ou['Ensure'] == 'absent':
        return True
    else:
        return False


def is_policy(ou):
    if 'Policy' in ou and ou['Policy'] != None and len(ou['Policy']) != 0:
        return True
    else:
        return False


#
# function print_specified_ou 
#
def print_specified_ou (parent_name, child_ou_list, indent, delete_flag):
    tab = '  '
    print tab*indent + parent_name + delete_flag + ':'
    indent+=1

    for ou in child_ou_list:
        if ensure_absent(ou):
            delete_flag = '[deleted]'
        else:
            delete_flag = ''
        if is_child(ou):
            print_specified_ou (ou['Name'], ou['OU'], indent, delete_flag)
        else:
            print tab*indent + ou['Name'] + delete_flag


#
# create_ou
#
def create_ou (parent_id, ou_name):
    new_ou = org_client.create_organizational_unit(
        ParentId=parent_id,
        Name=ou_name
    )
    return new_ou


# return ou name from an ou id
def get_ou_name(ou_id):
    ou = org_client.describe_organizational_unit(
        OrganizationalUnitId=ou_id
    )['OrganizationalUnit']
    return ou['Name']


#
# delete_ou
#
def delete_ou (ou_id):
    org_client.delete_organizational_unit(
        OrganizationalUnitId=ou_id,
    )

#
# get_policy_id
#
def get_policy_id_by_name(policy_name):
    response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
    for policy in response:
        if policy['Name'] == policy_name:
            return policy['Id']


# returns a list of service control policies attached to an OU
def get_policies (ou_id):
    response = org_client.list_policies_for_target(
        TargetId=ou_id,
        Filter='SERVICE_CONTROL_POLICY',
    )['Policies']
    return response

# returns sorted list of service control policy names from a list of policies
def get_policy_names (policy_list):
    names = []
    for policy in policy_list:
        names.append(policy['Name'])
    return sorted(names)

def policy_attached(policy_id, ou_id,):
    for policy in get_policies(ou_id): 
        if policy['Id'] == policy_id:
            return True
    return False

def attach_ou_policy (policy_id, ou_id,):
    response = org_client.attach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )




# print out the current org structure 
def display_existing_organization (parent_name, parent_id, indent):
    # query aws for child orgs
    child_ou_list = org_client.list_children(
        ParentId=parent_id,
        ChildType='ORGANIZATIONAL_UNIT'
    )['Children']
    # print parent ou name
    tab = '  '
    print
    print tab*indent + parent_name + ':'
    # look for policies
    policy_list = get_policies(parent_id)
    if len(policy_list) > 0:
        print tab*indent + tab + 'policies: ' + ' '.join(get_policy_names(policy_list))
    # look for child OUs
    if len(child_ou_list ) > 0:
        print tab*indent + tab + 'child_ou:'
        indent+=2
        for ou in child_ou_list:
            # recurse
            display_existing_organization(get_ou_name(ou['Id']), ou['Id'], indent)


#
# Recursive function to reconcile state of deployed OUs with OU specification
#
def manage_ou (specified_ou_list, parent_id):
    # query aws for child OU
    existing_ou_list = org_client.list_organizational_units_for_parent(
        ParentId=parent_id,
    )['OrganizationalUnits']

    for spec_ou in specified_ou_list:
        # check if this OU exists
        found = None
        for existing_ou in existing_ou_list:
            if spec_ou['Name'] == existing_ou['Name']:
                found = True
                found_ou_id = existing_ou['Id']

        if found:
            # test for child ou in ou_spec
            if is_child(spec_ou):
                # recurse
                manage_ou(spec_ou['OU'], found_ou_id)

            # manage service control policies
            if is_policy(spec_ou):
                for policy_name in spec_ou['Policy']:
                    policy_id = get_policy_id_by_name(policy_name)
                    if not policy_attached(policy_id, found_ou_id):
                        attach_ou_policy(policy_id, found_ou_id)

            # test if ou should be 'absent'
            if ensure_absent(spec_ou):
                print 'deleting OU', found_ou_id
                delete_ou(found_ou_id)

        elif not found and not ensure_absent(spec_ou):
            # create new ou
            print 'creating New ou', spec_ou['Name'], 'under parent Id', parent_id
            new_ou = create_ou(parent_id, spec_ou['Name'])

            # test for child ou
            if is_child(spec_ou) and \
                    isinstance(new_ou, dict) and \
                    'Id' in new_ou['OrganizationalUnit']:
                # recurse
                manage_ou(spec_ou['OU'], new_ou['OrganizationalUnit']['Id'])



print 'Specified org:'
print yaml_file
print
print 'Existing org:'
display_existing_organization('root', root_id, 0)
print
print 'Resulting org:'
manage_ou (org_spec['Org']['OU'], root_id)
display_existing_organization('root', root_id, 0)



#######################################################################

