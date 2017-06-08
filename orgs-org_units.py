#!/usr/bin/python
#
# Manage Organizaion OUs

# TODO:
# INPROGRESS merge account creation into this module
# DONE merge policy creation into this module
# add execption handling
# DONE add --dryrun flag
# DONE detach non-specified policies
# validate org_spec structures
# test if new ou exists before adding policies

import boto3
import yaml
import json
import sys
import os
import argparse # required 'pip install argparse'





#
# General functions
#

# Find a value in a list of dictionaries based on a known key:value.

# TODO: allow return of matching dictionary if no returnkey arg
# TODO: add error handling
#
# walk though a list of dictionaries, find the dictionary where
# searchkey => searchvalue, and return the value of 'returnkey' 
# from that dictionary.
#
# args:
#     dictlist:    data structure to search -  a list of type dictionary.
#     seachkey:    name of key to use as search criteria
#     seachvalue:  value to use as search criteria
#     returnkey:   name of key indexing the value to return
#
def find_in_dictlist (dictlist, searchkey, searchvalue, returnkey):

    # make sure keys exist
    if not filter(lambda d: searchkey in d and returnkey in d, dictlist):
        #keyerror
        return None

    # check for duplicate search values
    values = map(lambda d: d[searchkey], dictlist)
    if len(values) != len(set(values)):
        #duplicate search values
        return None

    # find the matching dictionary and return the indexed  value
    result = filter(lambda d: d[searchkey] == searchvalue, dictlist)
    if len(result) == 1:
        return result[0][returnkey]
    else:
        return None


# process command line args
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
    parser.add_argument('--build-ou',
        help='run ou management tasks',
        action='store_true'
    )
    parser.add_argument('--build-all',
        help='run all management tasks',
        action='store_true'
    )
    args = parser.parse_args()
    return args


# test if Ensure key is set to  absent
def ensure_absent(spec):
    if 'Ensure' in spec and spec['Ensure'] == 'absent':
        return True
    else:
        return False




#
# Account functions
#

## Unused
#def get_account_spec(spec_ou):
#    if 'Account' in spec_ou and spec_ou['Account'] != None:
#        return spec_ou['Account']

def get_account_id_by_name(account_name):
    return find_in_dictlist(deployed_accounts, 'Name', account_name, 'Id')

def get_account_email_by_name(account_name):
    return find_in_dictlist(deployed_accounts, 'Name', account_name, 'Email')

def get_parent_id(account_id):
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    if len(parents) == 1:
        return parents[0]['Id']
    else:
        #handle error
        #print 'account', account_id, 'has more than one parent', parents
        return None


# returns a list of accounts attached to an OU
def list_accounts_in_ou (ou_id):
    account_list = org_client.list_accounts_for_parent( ParentId=ou_id,)['Accounts']
    return sorted(map(lambda a: a['Name'], account_list))


#Unused
#def account_in_ou(account_id, ou_id):
#    if get_parent_id(account_id) == ou_id:
#        return True
#    else:
#        return False


def move_account(account_id, parent_id, ou_id):
    org_client.move_account(
        AccountId=account_id,
        SourceParentId=parent_id,
        DestinationParentId=ou_id
    )


##### in progres
# def create_account(a_spec):
#     print a_spec
#     response = org_client.create_account(
#         AccountName=a_spec['Name'],
#         Email=a_spec['Email']
#     )
#     if response['Status'] == '
# 

#def get_create_account_status(account_id):
#    response = org_client.list_create_account_status(account_id)


def display_provissioned_accounts():
    print
    print "Provissioned Accounts in Org:"
    for a_name in sorted(map(lambda a: a['Name'], deployed_accounts)):
        a_id = get_account_id_by_name(a_name)
        a_email = get_account_email_by_name(a_name)
        print "Name:\t\t%s\nEmail:\t\t%s\nId:\t\t%s\n" % (a_name, a_email, a_id)


def manage_accounts(account_spec):
    for a_spec in account_spec:
        if a_spec['Name'] != master_account:
            account_name = a_spec['Name']
            account_id = get_account_id_by_name(account_name)

            if not account_id:
                if not args.silent:
                    print "creating account: %s" % (account_name)
                if not args.dryrun:
                    create_account(a_spec)

            # locate account in correct ou
            # wait for account to be ready
            parent_id = get_parent_id(account_id)
            parent_ou_name = get_ou_name_by_id(parent_id)
            if a_spec['OU'] != parent_ou_name:
                if not args.silent:
                    print "moving account %s from ou %s to ou %s" % (account_name, parent_ou_name, a_spec['OU'] )
                if not args.dryrun:
                    #move_account(account_id, parent_id, ou_table[a_spec['OU']])
                    ou_id = get_ou_id_by_name(a_spec['OU'])
                    if ou_id:
                        move_account(account_id, parent_id, ou_id)
                    else:
                        print 'error: ou_id not found'




#
# Policy functions
#

def get_policy_id_by_name(policy_name):
    return find_in_dictlist(deployed_policies, 'Name', policy_name, 'Id')

def get_policy_description(policy_id):
    return find_in_dictlist(deployed_policies, 'Id', policy_id, 'Description')

def get_policy_content(policy_id):
    return org_client.describe_policy(PolicyId=policy_id)['Policy']['Content']


# returns a list of policy names attached to a given ou
def list_policies_in_ou (ou_id):
    policies_in_ou = org_client.list_policies_for_target(
        TargetId=ou_id,
        Filter='SERVICE_CONTROL_POLICY',
    )['Policies']
    return sorted(map(lambda ou: ou['Name'], policies_in_ou))


def get_policy_spec(spec_ou):
    if 'Policy' in spec_ou and spec_ou['Policy'] != None:
        return [default_policy] + spec_ou['Policy']
    else:
        return [default_policy]


def specify_policy_content(p_spec):
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (p_spec['Effect'], json.dumps(p_spec['Actions']))


def create_policy(p_spec):
    org_client.create_policy(
        Content=specify_policy_content(p_spec),
        Description=p_spec['Description'],
        Name=p_spec['Name'],
        Type='SERVICE_CONTROL_POLICY'
    )


def update_policy( p_spec, policy_id ):
    org_client.update_policy(
        PolicyId=policy_id,
        Content=specify_policy_content(p_spec),
        Description=p_spec['Description'],
    )


def delete_policy(policy_id):
    org_client.delete_policy(PolicyId=policy_id)


# verify if a policy is attached to an ou
def policy_attached(policy_id, ou_id,):
    policy_targets = org_client.list_targets_for_policy(PolicyId=policy_id)['Targets']
    if ou_id in map(lambda ou: ou['TargetId'], policy_targets):
        return True
    return False


# attach a policy to an ou
def attach_policy (policy_id, ou_id,):
    org_client.attach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )


# detach a policy from an ou
def detach_policy (policy_id, ou_id,):
    org_client.detach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )


# pretty print exiting policies
def display_provissioned_policies():
    print
    print "Provissioned Service Control Policies:"
    for policy in deployed_policies:
        print "Name:\t\t%s\nDescription:\t%s\nId:\t\t%s" % (policy['Name'], policy['Description'], policy['Id'])
        print "Content:\t%s\n" % get_policy_content(policy['Id'])


# walk though policy_spec and make stuff happen
def manage_policies(policy_spec):
    for p_spec in policy_spec:
        if p_spec['Name'] != default_policy:
            policy_name = p_spec['Name']
            policy_id = get_policy_id_by_name(policy_name)

            if policy_id and ensure_absent(p_spec):
                if not args.silent:
                    print "deleting policy: %s" % (policy_name)
                if not args.dryrun:
                    delete_policy(policy_id)
    
            else:
                if not policy_id:
                    if not args.silent:
                        print "creating policy: %s" % (policy_name)
                    if not args.dryrun:
                        create_policy(p_spec)
    
                else:
                    if p_spec['Description'] != get_policy_description(policy_id) \
                            or specify_policy_content(p_spec) != get_policy_content(policy_id):
                        if not args.silent:
                            print "updating policy: %s" % (policy_name)
                        if not args.dryrun:
                            update_policy(p_spec, policy_id)




#
# OrganizaionalUnit functions
#

def children_in_ou_spec(spec_ou):
    if 'OU' in spec_ou and spec_ou['OU'] != None and len(spec_ou['OU']) != 0:
        return True
    return False

def get_ou_id_by_name(ou_name):
    return find_in_dictlist(deployed_ou, 'Name', ou_name, 'Id')


# create an ou under specified parent
def create_ou (parent_id, ou_name):
    return org_client.create_organizational_unit(
        ParentId=parent_id,
        Name=ou_name
    )['OrganizationalUnit']


# delete ou
def delete_ou (ou_name):
    if len(ou_table[ou_name]['Children']) > 0:
        print "OU %s has children. Can not delete." % ou_name
    else:
        org_client.delete_organizational_unit (
            OrganizationalUnitId=ou_table[ou_name]['Id']
        )

# return ou name from an ou id
def get_ou_name_by_id(ou_id):
    if ou_id == root_id:
        return 'root'
    else:
        return find_in_dictlist(deployed_ou, 'Id', ou_id, 'Name')


# recursive function to display the existing org structure 
def display_provissioned_ou (parent_name, parent_id, indent):
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
    policy_names = list_policies_in_ou(parent_id)
    if len(policy_names) > 0:
        print tab*indent + tab + 'policies: ' + ', '.join(policy_names)
    # look for account
    account_list = list_accounts_in_ou(parent_id)
    if len(account_list) > 0:
        print tab*indent + tab + 'accounts: ' + ', '.join(account_list)
    # look for child OUs
    if len(child_ou_list ) > 0:
        print tab*indent + tab + 'child_ou:'
        indent+=2
        for ou in child_ou_list:
            # recurse
            display_provissioned_ou(get_ou_name_by_id(ou['Id']), ou['Id'], indent)


# attach or detach policies to an ou based on the spec for this ou
def manage_policy_attachments(spec_ou, ou_id):
    # attach specified policies
    p_spec = get_policy_spec(spec_ou)
    for policy_name in p_spec:
        policy_id = get_policy_id_by_name(policy_name)

        if not policy_attached(policy_id, ou_id) and not ensure_absent(spec_ou):
            if not args.silent:
                print "attaching policy %s to OU %s" % (policy_name, spec_ou['Name'])
            if not args.dryrun:
                attach_policy(policy_id, ou_id)

    # detach unspecified policies
    policy_list = list_policies_in_ou(ou_id)
    for policy_name in policy_list:
        if policy_name not in p_spec and not ensure_absent(spec_ou):
            policy_id = get_policy_id_by_name(policy_name)
            if not args.silent:
                print "detaching policy %s from OU %s" % (policy_name, spec_ou['Name'])
            if not args.dryrun:
                detach_policy(policy_id, ou_id)


# build ou lookup table and gether all ou into list (recursive)
def build_ou_table(parent_name, parent_id, ou_table, deployed_ou):
    children_ou = org_client.list_organizational_units_for_parent(
        ParentId=parent_id
    )['OrganizationalUnits']

    for ou in children_ou:
        deployed_ou.append(ou)
        if not ou['Name'] in ou_table:
            ou_table[ou['Name']] = {}
        ou_table[ou['Name']]['ParentId'] = parent_id
        build_ou_table(ou['Name'], ou['Id'], ou_table, deployed_ou)

    if not parent_name in ou_table:
        ou_table[parent_name] = {}
    ou_table[parent_name]['Id'] = parent_id
    ou_table[parent_name]['Children'] = map(lambda ou: ou['Name'], children_ou)


#
# manage_ou()
#
# Recursive function to reconcile state of deployed OUs with OU specification
#def manage_ou (specified_ou_list, parent_id):
#
#    # create lookup table of existing child OUs: {name:ID}
#    existing_ou_list = org_client.list_organizational_units_for_parent(
#        ParentId=parent_id,
#    )['OrganizationalUnits']
#    existing_ou_names = {}
#    for ou in existing_ou_list:
#        existing_ou_names[ou['Name']] = ou['Id']
#
#    # check if each specified OU exists
#    for spec_ou in specified_ou_list:
#        if spec_ou['Name'] in existing_ou_names.keys():
#            existing_ou_id = existing_ou_names[spec_ou['Name']]
#            # test for child ou in ou_spec
#            if children_in_ou_spec(spec_ou):
#                # recurse
#                manage_ou(spec_ou['OU'], existing_ou_id)
#            # test if ou should be 'absent'
#            if ensure_absent(spec_ou):
#                if not args.silent:
#                    print 'deleting OU', spec_ou['Name']
#                if not args.dryrun:
#                    delete_ou(existing_ou_id)
#            else:
#                # manage policies
#                manage_policy_attachments(spec_ou, existing_ou_id)
#
#        # ou does not exist
#        elif not ensure_absent(spec_ou):
#            # create new ou
#            if not args.silent:
#                print "creating new ou %s under parent %s" % (spec_ou['Name'], get_ou_name_by_id(parent_id))
#            if not args.dryrun: 
#                new_ou = create_ou(parent_id, spec_ou['Name'])
#                manage_policy_attachments(spec_ou, new_ou['OrganizationalUnit']['Id'])
#                # test if new ou should have children
#                if children_in_ou_spec(spec_ou) and isinstance(new_ou, dict) \
#                        and 'Id' in new_ou['OrganizationalUnit']:
#                    # recurse
#                    manage_ou(spec_ou['OU'], new_ou['OrganizationalUnit']['Id'])


def manage_ou (ou_spec_list, parent_name):

    for ou_spec in ou_spec_list:

        # ou exists
        if ou_spec['Name'] in ou_table[parent_name]['Children']:
            if children_in_ou_spec(ou_spec):
                # recurse
                manage_ou(ou_spec['OU'], ou_spec['Name'])
            if ensure_absent(ou_spec):
                if not args.silent:
                    print 'deleting OU', ou_spec['Name']
                if not args.dryrun:
                    delete_ou(ou_spec['Name'])
            else:
                manage_policy_attachments(ou_spec, ou_table[ou_spec['Name']]['Id'])

        # ou does not exist
        elif not ensure_absent(ou_spec):
            if not args.silent:
                print "creating new ou %s under parent %s" % (ou_spec['Name'], parent_name)
            if not args.dryrun: 
                new_ou = create_ou(ou_table[parent_name]['Id'], ou_spec['Name'])
                manage_policy_attachments(ou_spec, new_ou['Id'])
                if children_in_ou_spec(ou_spec) and isinstance(new_ou, dict) \
                        and 'Id' in new_ou:
                    # recurse
                    manage_ou(ou_spec['OU'], new_ou['Name'])





#
# Command line args
#
args = parse_args()

if args.dryrun or args.report_only:
    args.silent = False

if args.build_account == False and \
        args.build_policy == False  and \
        args.build_ou == False:
    args.build_all = True

if args.build_all:
    args.build_account = True
    args.build_policy = True
    args.build_ou = True



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

# build lookup data structures for accounts, policies and OUs
deployed_accounts = org_client.list_accounts()['Accounts']
deployed_policies = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
deployed_ou = []
ou_table = {}
build_ou_table('root', root_id, ou_table, deployed_ou)


# load spec-file
org_spec = yaml.load(args.spec_file.read())

# all orgs have at least this default policy
for policy in org_spec['policy_spec']:
    if 'Default' in policy and policy['Default'] == True:
        default_policy = policy['Name']

# find the Master account name
for account in org_spec['account_spec']:
    if 'Master' in account and account['Master'] == True:
        master_account = account['Name']






#
# Main
#

if args.report_only:
    display_provissioned_policies()
    display_provissioned_accounts()
    print
    print 'Provissioned Organizational Units in Org:'
    display_provissioned_ou('root', root_id, 0)


if args.dryrun: print "This is a dry run!"

if args.build_policy:
    manage_policies(org_spec['policy_spec'])
    if not args.silent and not args.no_report: display_provissioned_policies()

if args.build_account:
    manage_accounts(org_spec['account_spec'])
    if not args.silent and not args.no_report: display_provissioned_accounts()

if args.build_ou:
    manage_ou (org_spec['ou_spec'], 'root')
    if not args.silent and not args.no_report:
        print
        print 'Provissioned Organizational Units in Org:'
        display_provissioned_ou('root', root_id, 0)

