#!/usr/bin/python
#
# Manage Organizaion OUs

# TODO:
# merge account and policy creation into this module
# add execption handling
# DONE add --dryrun flag
# manage accounts
# DONE detach non-specified policies
# validate policy spec is an array of str
# test if new ou exists before adding policies

import boto3
import yaml
import json
import sys
import os
import argparse # required 'pip install argparse'


#
# process command line args
#
def parse_args():
    parser = argparse.ArgumentParser(description='Manage AWS Organization')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--spec-file',
        type=file,
        help='file containing organization specification in yaml format'
    )
    group.add_argument('--report-only',
        help='display organization status report only. do not process org spec',
        action='store_true'
    )
    parser.add_argument('--no-report',
        help='suppress reporting. display actions only',
        action='store_true'
    )
    parser.add_argument('--dryrun',
        help='dryrun mode. show pending changes, but do nothing',
        action='store_true'
    )
    parser.add_argument('--silent',
        help='silent mode. overriden when --dryrun is set',
        action='store_true'
    )
    parser.add_argument('--build-policy',
        help='run policy management tasks',
        action='store_true'
    )
    parser.add_argument('--build-account',
        help='run account management tasks',
        action='store_true'
    )
    parser.add_argument('--build-all',
        help='run all management tasks',
        action='store_true'
    )
    args = parser.parse_args()
    return args



#
# Global Variables
#

# set up aws client for orgs
org_client = boto3.client('organizations')

# determine the Organization Root ID
root_id = org_client.list_roots()['Roots'][0]['Id']

# enable policy type in the Organization root
## TODO: this can be cleaner
policy_types = org_client.describe_organization()['Organization']['AvailablePolicyTypes']
for p_type in policy_types:
    if p_type['Type'] == 'SERVICE_CONTROL_POLICY' and p_type['Status'] != 'ENABLED':
        response = org_client.enable_policy_type(
            RootId=root_id,
            PolicyType='SERVICE_CONTROL_POLICY'
        )

# build account lookup table
account_table = {}
for account in org_client.list_accounts()['Accounts']:
    account_table[account['Name']] = account['Id']

# build policy lookup table
policy_table = {}
for policy in org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']:
    policy_table[policy['Name']] = policy['Id']

# build ou lookup table (recursive)
def build_ou_table(parent_id, ou_table):
    # query aws for child orgs
    for ou in org_client.list_organizational_units_for_parent(ParentId=parent_id)['OrganizationalUnits']:
        ou_table[ou['Name']] = ou['Id']
        build_ou_table(ou['Id'], ou_table)
    return
ou_table = {}
build_ou_table(root_id, ou_table)






#
# get command line args
#
args = parse_args()

# don't be silent when doing dryrun or reporting
if args.dryrun or args.report_only: args.silent = False

# parse org_spec globals from from yaml file
if not args.report_only:
    org_spec = yaml.load(args.spec_file.read())
    ou_spec = org_spec['ou_spec']
    policy_spec = org_spec['policy_spec']
    account_spec = org_spec['account_spec']

    # all orgs have at least this default policy
    for policy in policy_spec:
        if 'Default' in policy and policy['Default'] == True:
            default_policy = policy['Name']
    
    # find the Master account name
    for account in account_spec:
        if 'Master' in account and account['Master'] == True:
            master_account = account['Name']






#
# Specification parsing functions
#
def is_child(spec_ou):
    if 'OU' in spec_ou and spec_ou['OU'] != None and len(spec_ou['OU']) != 0:
        return True
    else:
        return False

def ensure_absent(spec_ou):
    if 'Ensure' in spec_ou and spec_ou['Ensure'] == 'absent':
        return True
    else:
        return False

def get_policy_spec(spec_ou):
    if 'Policy' in spec_ou and spec_ou['Policy'] != None:
        return [default_policy] + spec_ou['Policy']
    else:
        return [default_policy]

def get_account_spec(spec_ou):
    if 'Account' in spec_ou and spec_ou['Account'] != None:
        return spec_ou['Account']




#
# OrganizaionalUnit functions
#

# create an ou under specified parent
def create_ou (parent_id, ou_name):
    new_ou = org_client.create_organizational_unit(
        ParentId=parent_id,
        Name=ou_name
    )
    return new_ou

# delete ou
def delete_ou (ou_id):
    existing_ou_list = org_client.list_organizational_units_for_parent(
        ParentId=ou_id,
    )['OrganizationalUnits']
    if len(existing_ou_list) > 0:
        print "OU %s has children. Can not delete." % get_ou_name(ou_id)
    else:
        org_client.delete_organizational_unit(
            OrganizationalUnitId=ou_id,
        )

# return ou name from an ou id
def get_ou_name(ou_id):
    if ou_id == root_id:
        return 'Root'
    else:
        ou = org_client.describe_organizational_unit(
            OrganizationalUnitId=ou_id
        )['OrganizationalUnit']
        return ou['Name']

# # return True is an ou exists
# def ou_exists(ou_id):
#     ou = org_client.describe_organizational_unit( OrganizationalUnitId=ou_id)



#
# Account functions
#

def account_exists(account_name, account_table):
    return account_name in account_table.keys()

def get_account_id_by_name(account_name, account_table):
    if account_name in account_table.keys():
        return account_table[account_name]
    else:
        return None

def get_parent_id(account_id):
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    if len(parents) == 1:
        return parents[0]['Id']
    else:
        #handle error
        print 'account', account_id, 'has more than one parent', parents
        return None

# returns a list of accounts attached to an OU
def get_accounts_in_ou (ou_id):
    account_list = org_client.list_accounts_for_parent(
        ParentId=ou_id,
    )['Accounts']
    return account_list

def account_in_ou(account_id, ou_id):
    if get_parent_id(account_id) == ou_id:
        return True
    else:
        return False

# returns sorted list of account names from a list of accounts
def get_account_names (account_list):
    names = []
    for account in account_list:
        names.append(account['Name'])
    return sorted(names)




#
# Policy functions
#

def get_policy( policy_id ):
    return org_client.describe_policy(PolicyId=policy_id)['Policy']

def create_policy_content(p_spec):
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (p_spec['Effect'], json.dumps(p_spec['Actions']))

def create_policy(p_spec):
    response = org_client.create_policy(
        Content=create_policy_content(p_spec),
        Description=p_spec['Description'],
        Name=p_spec['Name'],
        Type='SERVICE_CONTROL_POLICY'
    )

def update_policy( p_spec, policy_id ):
    response = org_client.update_policy(
        PolicyId=policy_id,
        Content=create_policy_content(p_spec),
        Description=p_spec['Description'],
    )

def delete_policy(policy_id):
    org_client.delete_policy(PolicyId=policy_id)

def display_provissioned_policies():
    print
    print "Provissioned Service Control Policies:"
    print
    for policy in org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']:
        print "Name:\t\t%s\nDescription:\t%s\nId:\t\t%s" % (policy['Name'], policy['Description'], policy['Id'])
        print "Content:\t%s\n" % get_policy(policy['Id'])['Content']


# get policy id based on it's name
def get_policy_id_by_name(policy_name):
    return policy_table[policy_name]

def policy_exists(policy_name):
    if policy_name in policy_table.keys():
        return True
    else:
        return False

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

# verify if a policy is attached to an ou
def policy_attached(policy_id, ou_id,):
    for policy in get_policies(ou_id): 
        if policy['Id'] == policy_id:
            return True
    return False

# attach a policy to an ou
def attach_policy (policy_id, ou_id,):
    response = org_client.attach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )

# detach a policy to an ou
def detach_policy (policy_id, ou_id,):
    org_client.detach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )

# walk though policy_spec and make stuff happen
def manage_policies(policy_spec):
    for p_spec in policy_spec:
        if p_spec['Name'] != default_policy:
            policy_name = p_spec['Name']

            if 'Ensure' in p_spec and p_spec['Ensure'] == 'absent' and policy_exists(policy_name):
                if not args.silent:
                    print "deleting policy: %s %s" % (policy_name, policy_table[policy_name])
                if not args.dryrun:
                    delete_policy(policy_table[policy_name])
    
            else:
                if not policy_exists(policy_name):
                    if not args.silent:
                        print "creating policy: %s" % (policy_name)
                    if not args.dryrun:
                        create_policy(p_spec)
    
                else:
                    policy = get_policy(policy_table[policy_name])
                    #print policy['PolicySummary']['Description']
                    if p_spec['Description'] != policy['PolicySummary']['Description'] or create_policy_content(p_spec) != policy['Content']:
                        if not args.silent:
                            print "updating policy: %s" % (policy_name)
                        if not args.dryrun:
                            update_policy(p_spec, policy_table[policy_name])






#
# display_existing_organization()
#
# recursive function to display the existing org structure 
def display_existing_organization (parent_name, parent_id, indent):
    # query aws for child orgs
    child_ou_list = org_client.list_children(
        ParentId=parent_id,
        ChildType='ORGANIZATIONAL_UNIT'
    )['Children']
    # print parent ou name
    tab = '  '
    #print
    print tab*indent + parent_name + ':'
    # look for policies
    policy_list = get_policies(parent_id)
    if len(policy_list) > 0:
        print tab*indent + tab + 'policies: ' + ', '.join(get_policy_names(policy_list))
    # look for account
    account_list = get_accounts_in_ou(parent_id)
    if len(account_list) > 0:
        print tab*indent + tab + 'accounts: ' + ', '.join(get_account_names(account_list))
    # look for child OUs
    if len(child_ou_list ) > 0:
        print tab*indent + tab + 'child_ou:'
        indent+=2
        for ou in child_ou_list:
            # recurse
            display_existing_organization(get_ou_name(ou['Id']), ou['Id'], indent)


# attach or detach policies to an ou based on the spec for this ou
def manage_policy_attachments(spec_ou, existing_ou_id):
    # attach specified policies
    policy_spec = get_policy_spec(spec_ou)
    for policy_name in policy_spec:
        policy_id = get_policy_id_by_name(policy_name)
        if not policy_attached(policy_id, existing_ou_id) and not ensure_absent(spec_ou):
            if not args.silent:
                print "attaching policy %s to OU %s" % (policy_name, spec_ou['Name'])
            if not args.dryrun:
                attach_policy(policy_id, existing_ou_id)
    # detach unspecified policies
    existing_policy_list = get_policy_names(get_policies(existing_ou_id))
    for policy_name in existing_policy_list:
        if policy_name not in policy_spec and not ensure_absent(spec_ou):
            policy_id = get_policy_id_by_name(policy_name)
            if not args.silent:
                print "detaching policy %s from OU %s" % (policy_name, spec_ou['Name'])
            if not args.dryrun:
                detach_policy(policy_id, existing_ou_id)



#
# manage_ou()
#
# Recursive function to reconcile state of deployed OUs with OU specification
def manage_ou (specified_ou_list, parent_id):

    # create lookup table of existing child OUs: {name:ID}
    existing_ou_list = org_client.list_organizational_units_for_parent(
        ParentId=parent_id,
    )['OrganizationalUnits']
    existing_ou_names = {}
    for ou in existing_ou_list:
        existing_ou_names[ou['Name']] = ou['Id']

    # check if each specified OU exists
    for spec_ou in specified_ou_list:
        if spec_ou['Name'] in existing_ou_names.keys():
            existing_ou_id = existing_ou_names[spec_ou['Name']]
            # test for child ou in ou_spec
            if is_child(spec_ou):
                # recurse
                manage_ou(spec_ou['OU'], existing_ou_id)
            # test if ou should be 'absent'
            if ensure_absent(spec_ou):
                if not args.silent:
                    print 'deleting OU', spec_ou['Name']
                if not args.dryrun:
                    delete_ou(existing_ou_id)
            else:
                # manage policies
                manage_policy_attachments(spec_ou, existing_ou_id)

        # ou does not exist
        elif not ensure_absent(spec_ou):
            # create new ou
            if not args.silent:
                print "creating new ou %s under parent %s" % (spec_ou['Name'], get_ou_name(parent_id))
            if not args.dryrun: 
                new_ou = create_ou(parent_id, spec_ou['Name'])
                manage_policy_attachments(spec_ou, new_ou['OrganizationalUnit']['Id'])
                # test if new ou should have children
                if is_child(spec_ou) and isinstance(new_ou, dict) \
                        and 'Id' in new_ou['OrganizationalUnit']:
                    # recurse
                    manage_ou(spec_ou['OU'], new_ou['OrganizationalUnit']['Id'])



#
# Main
#

if args.build_policy:
    manage_policies(org_spec['policy_spec'])
    display_provissioned_policies()
#if args.silent:
#    manage_ou (ou_spec['OU'], root_id)
#
#elif args.report_only:
#    print 'Existing org:'
#    display_existing_organization('root', root_id, 0)
#
#else:
#    if not args.no_report:
#        print 'Existing org:'
#        display_existing_organization('root', root_id, 0)
#        print
#
#    if args.dryrun:
#        print "This is a dry run!"
#        print "Pending Actions:"
#    else:
#        print "Actions taken:"
#
#    manage_ou (ou_spec['OU'], root_id)
#
#    if not args.no_report and not args.dryrun:
#        print
#        print 'Resulting org:'
#        display_existing_organization('root', root_id, 0)




