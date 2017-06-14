#!/usr/bin/python

"""
a module to manage AWS Organizations
"""

import boto3
import yaml
import json
import sys
import os
import argparse
from botocore.exceptions import (NoCredentialsError, ClientError)
import inspect




#
# General functions
#

def parse_args():
    """
    process command line args
    """
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
    parser.add_argument('--dry-run',
        help='dry run mode. show pending changes, but do nothing',
        action='store_true'
    )
    parser.add_argument('--silent',
        help='silent mode. overriden when --dry-run is set',
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
    parser.add_argument('--create-accounts',
        help='create new AWS accounts in Org per account specifation',
        action='store_true'
    )

    args = parser.parse_args()
    if args.dry_run or args.report_only:
        args.silent = False
    if args.build_account == False and \
            args.build_policy == False  and \
            args.build_ou == False:
        args.build_all = True
    if args.build_all:
        args.build_account = True
        args.build_policy = True
        args.build_ou = True
    return args


def get_root_id(org_client):
    """
    Query deployed AWS Organization for its Root ID.
    """
    try:
        root_id = org_client.list_roots()['Roots'][0]['Id']
        return root_id
    except NoCredentialsError as e:
        print sys.argv[0]
        print e
        print "at function:", inspect.getframeinfo(inspect.currentframe())[2]
        print "in module:", __name__
        raise SystemExit
    except ClientError as e:
        print e
        print "at function:", inspect.getframeinfo(inspect.currentframe())[2]
        print "in module:", __name__
        raise SystemExit


def parse_org_specification(args):
    """
    load yaml 'spec-file' into dictionary.
    set global vars:
        org_spec
        default_policy
        master_account
    """
    global org_spec, default_policy, master_account
    org_spec = yaml.load(args.spec_file.read())
    for policy in org_spec['policy_spec']:
        if 'Default' in policy and policy['Default'] == True:
            default_policy = policy['Name']
    for account in org_spec['account_spec']:
        if 'Master' in account and account['Master'] == True:
            master_account = account['Name']


def enable_policy_type_in_root(org_client, root_id):
    """
    ensure policy type 'SERVICE_CONTROL_POLICY' is enabled in the
    organization root.
    """
    p_type = org_client.describe_organization()['Organization']['AvailablePolicyTypes'][0]
    if p_type['Type'] == 'SERVICE_CONTROL_POLICY' and p_type['Status'] != 'ENABLED':
        org_client.enable_policy_type(
            RootId=root_id,
            PolicyType='SERVICE_CONTROL_POLICY'
        )


def ensure_absent(spec):
    """
    test if an 'Ensure' key is set to absent in dictionary 'spec'
    """
    if 'Ensure' in spec and spec['Ensure'] == 'absent':
        return True
    else:
        return False


def lookup(dlist, lkey, lvalue, rkey=None):
    """
    Use a known key:value pair to lookup a dictionary in a list of
    dictionaries.  Return the dictonary or None.  If rkey is provided,
    return the value referenced by rkey or None.  If more than one
    dict matches, raise an error.
    args:
        dlist:   lookup table -  a list of dictionaries
        lkey:    name of key to use as lookup criteria
        lvalue:  value to use as lookup criteria
        key:     (optional) name of key referencing a value to return
    """
    items = [d for d in dlist
             if lkey in d
             and d[lkey] == lvalue]
    if not items:
        return None
    if len(items) > 1:
        raise RuntimeError(
            "Data Error: lkey:lvalue lookup matches multiple items in dlist"
        )
    if rkey:
        if rkey in items[0]:
            return items[0][rkey]
        return None
    return items[0]


#def find_in_dictlist (dictlist, searchkey, searchvalue, returnkey):
#    """
#    Find a value in a list of dictionaries based on a known key:value.
#    Return found value or 'None'.
#
#    args:
#        dictlist:    data structure to search -  a list of type dictionary.
#        seachkey:    name of key to use as search criteria
#        seachvalue:  value to use as search criteria
#        returnkey:   name of key indexing the value to return
#    """
#
#    # make sure keys exist
#    if not filter(lambda d: searchkey in d and returnkey in d, dictlist):
#        #error: key not found
#        return None
#
#    # check for duplicate search values
#    values = map(lambda d: d[searchkey], dictlist)
#    if len(values) != len(set(values)):
#        # error: duplicate search values
#        return None
#
#    # find the matching dictionary and return the indexed value
#    result = filter(lambda d: d[searchkey] == searchvalue, dictlist)
#    if len(result) == 1:
#        return result[0][returnkey]
#    else:
#        return None





#
# Account functions
#

## Unused
#def get_account_spec(ou_spec):
#    if 'Account' in ou_spec and ou_spec['Account'] != None:
#        return ou_spec['Account']
#
#Unused
#def account_in_ou(account_id, ou_id):
#    if get_parent_id(account_id) == ou_id:
#        return True
#    else:
#        return False


#def get_account_id_by_name(account_name):
#    """
#    search 'deployed_account' dictlist for 'account_name'. return the
#    acccount Id or 'None'.
#    """
#    return find_in_dictlist(deployed_accounts, 'Name', account_name, 'Id')
#    lookup(deployed_accounts, 'Name', account_name, 'Id')


#def get_account_email_by_name(account_name):
#    """
#    search 'deployed_account' dictlist for 'account_name'. return the
#    acccount Email or 'None'.
#    """
#    return find_in_dictlist(deployed_accounts, 'Name', account_name, 'Email')


def scan_deployed_accounts(org_client):
    """
    Query AWS Organization for successfully created accounts.
    Returns a list of dictionary.
    """
    deployed_accounts = []
    created_accounts = org_client.list_create_account_status(
        States=['SUCCEEDED']
    )['CreateAccountStatuses']
    for account_id in map(lambda a: a['AccountId'], created_accounts):
        deployed_accounts.append( org_client.describe_account(AccountId=account_id)['Account'] )
    return deployed_accounts


def get_parent_id(org_client, account_id):
    """
    Query deployed AWS organanization for 'account_id. Return the 'Id' of the
    parent OrganizationalUnit or 'None'.
    """
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    if len(parents) == 1:
        return parents[0]['Id']
    else:
        #handle error
        #print 'account', account_id, 'has more than one parent', parents
        return None


def list_accounts_in_ou(org_client, ou_id):
    """
    Query deployed AWS organanization for accounts contained in
    OrganizationalUnit ('ou_id').  Return a list of accounts
    (list of type dict).
    """
    account_list = org_client.list_accounts_for_parent(
        ParentId=ou_id
    )['Accounts']
    return sorted(map(lambda a: a['Name'], account_list))


def create_account(org_client, a_spec):
    return org_client.create_account(
        AccountName=a_spec['Name'],
        Email=a_spec['Email']
    )['CreateAccountStatus']['State']


def move_account(org_client, account_id, parent_id, target_id):
    """
    Alter deployed AWS organanization. Move account referenced by 'account_id'
    out of current containing OU ('parent_id') and into target OU ('target_id')
    """
    org_client.move_account(
        AccountId=account_id,
        SourceParentId=parent_id,
        DestinationParentId=target_id
    )
    # handle exception


def display_provissioned_accounts(deployed_accounts):
    """
    Print report of currently deployed accounts in AWS Organization.
    """
    print
    print "_____________________________"
    print "Provissioned Accounts in Org:"
    for a_name in sorted(map(lambda a: a['Name'], deployed_accounts)):
        a_id = lookup(deployed_accounts, 'Name', a_name, 'Id')
        a_email = lookup(deployed_accounts, 'Name', a_name, 'Email')
        print "Name:\t\t%s\nEmail:\t\t%s\nId:\t\t%s\n" % (a_name, a_email, a_id)


def manage_accounts(org_client, args, deployed_accounts, deployed_ou, account_spec):
    """
    Alter deployed AWS Organization.  Ensure accounts are contained
    by designated OrganizationalUnits based on account specification
    ('account_spec').
    """
    global change_counter
    for a_spec in account_spec:
        if a_spec['Name'] != master_account:
            account_name = a_spec['Name']
            account_id = lookup(deployed_accounts, 'Name', account_name, 'Id')

            if not account_id:
                if args.create_accounts:
                    change_counter += 1
                    if not args.silent:
                        print "creating account: %s" % (account_name)
                    if not args.dry_run:
                        account_state = create_account(org_client, a_spec)
                else:
                    if not args.silent:
                        print "Warning: account %s not in Org." % (account_name)
                        print "Use '--create-accounts' option to create new accounts."

            else:
                # locate account in correct ou
                parent_id = get_parent_id(org_client, account_id)
                parent_ou_name = lookup(deployed_ou, 'Id', parent_id, 'Name')
                if a_spec['OU'] != parent_ou_name:
                    change_counter += 1
                    if not args.silent:
                        print "moving account %s from ou %s to ou %s" % (account_name, parent_ou_name, a_spec['OU'] )
                    if not args.dry_run:
                        ou_id = lookup(deployed_ou, 'Name', a_spec['OU'], 'Id')
                        if ou_id:
                            move_account(org_client, account_id, parent_id, ou_id)
                        else:
                            # handle execption: ou_id not found
                            print 'error: ou_id not found'




#
# Policy functions
#

#def get_policy_id_by_name(policy_name):
#    """
#    search 'deployed_policies' dictlist for 'policy_name'. return the
#    policy Id or 'None'.
#    """
#    return find_in_dictlist(deployed_policies, 'Name', policy_name, 'Id')


#def get_policy_description(policy_id):
#    """
#    search 'deployed_policies' dictlist for 'policy_name'. return the
#    policy Description or 'None'.
#    """
#    return find_in_dictlist(deployed_policies, 'Id', policy_id, 'Description')


def get_policy_content(org_client, policy_id):
    """
    Query deployed AWS Organization.  Return the policy content (json string)
    accociated with the Service Control Policy referenced by 'policy_id'.
    """
    return org_client.describe_policy(PolicyId=policy_id)['Policy']['Content']
    # handle exception


def list_policies_in_ou (org_client, ou_id):
    """
    Query deployed AWS organanization.  Return a list (of type dict)
    of policies attached to OrganizationalUnit referenced by 'ou_id'.
    """
    policies_in_ou = org_client.list_policies_for_target(
        TargetId=ou_id,
        Filter='SERVICE_CONTROL_POLICY',
    )['Policies']
    return sorted(map(lambda ou: ou['Name'], policies_in_ou))


def get_policy_spec_for_ou(ou_spec):
    """
    Search 'ou_spec' dict for a list of policy names specified for attachment
    to this OrganizationalUnit.  Prepend the 'default_policy' to this list
    and return list.
    """
    if 'Policy' in ou_spec and ou_spec['Policy'] != None:
        return [default_policy] + ou_spec['Policy']
    else:
        return [default_policy]


def specify_policy_content(p_spec):
    """
    Compose and return (as json string) a policy content specification as
    per the given policy spec ('p_spec').
    """
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (p_spec['Effect'], json.dumps(p_spec['Actions']))


def create_policy(org_client, p_spec):
    """
    Create a new Service Control Policy in the AWS Organization based on
    a policy specification ('p_spec').
    """
    org_client.create_policy (
        Content=specify_policy_content(p_spec),
        Description=p_spec['Description'],
        Name=p_spec['Name'],
        Type='SERVICE_CONTROL_POLICY'
    )


def update_policy(org_client,  p_spec, policy_id ):
    """
    Update a deployed Service Control Policy ('policy_id') in the
    AWS Organization based on a policy specification ('p_spec').
    """
    org_client.update_policy(
        PolicyId=policy_id,
        Content=specify_policy_content(p_spec),
        Description=p_spec['Description'],
    )


def delete_policy(org_client, policy_id):
    """
    Delete a deployed Service Control Policy ('policy_id') in the
    AWS Organization.
    """
    org_client.delete_policy(PolicyId=policy_id)


def policy_attached(org_client, policy_id, ou_id,):
    """
    Test if a deployed Service Control Policy ('policy_id') is attached to a
    given OrganizationalUnit ('ou_id').  Returns a boolean.
    """
    policy_targets = org_client.list_targets_for_policy (
        PolicyId=policy_id
    )['Targets']
    if ou_id in map(lambda ou: ou['TargetId'], policy_targets):
        return True
    return False


def attach_policy (org_client, policy_id, ou_id,):
    """
    Attach a deployed Service Control Policy ('policy_id') to a given
    OrganizationalUnit ('ou_id').
    """
    org_client.attach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )


def detach_policy (org_client, policy_id, ou_id,):
    """
    Detach a deployed Service Control Policy ('policy_id') from a given
    OrganizationalUnit ('ou_id').
    """
    org_client.detach_policy (
        PolicyId=policy_id,
        TargetId=ou_id
    )


def display_provissioned_policies(org_client, deployed_policies):
    """
    Print report of currently deployed Service Control Policies in
    AWS Organization.
    """
    print
    print "______________________________________"
    print "Provissioned Service Control Policies:"
    for policy in deployed_policies:
        print "Name:\t\t%s\nDescription:\t%s\nId:\t\t%s" % (
            policy['Name'],
            policy['Description'],
            policy['Id']
        )
        print "Content:\t%s\n" % get_policy_content(org_client, policy['Id'])


def manage_policies(org_client, args, deployed_policies, policy_spec):
    """
    Manage Service Control Policies in the AWS Organization.  Make updates
    according to the policy specification ('policy_spec').
    """
    global change_counter
    for p_spec in policy_spec:
        if p_spec['Name'] != default_policy:
            policy_name = p_spec['Name']
            policy_id = lookup(deployed_policies, 'Name', policy_name, 'Id')

            if policy_id and ensure_absent(p_spec):
                change_counter += 1
                if not args.silent:
                    print "deleting policy: %s" % (policy_name)
                if not args.dry_run:
                    delete_policy(org_client, policy_id)

            else:
                if not policy_id:
                    change_counter += 1
                    if not args.silent:
                        print "creating policy: %s" % (policy_name)
                    if not args.dry_run:
                        create_policy(org_client, p_spec)

                else:
                    if p_spec['Description'] != lookup(deployed_policies, 'Id', policy_id, 'Description') or specify_policy_content(p_spec) != get_policy_content(org_client, policy_id):
                        change_counter += 1
                        if not args.silent:
                            print "updating policy: %s" % (policy_name)
                        if not args.dry_run:
                            update_policy(org_client, p_spec, policy_id)




#
# OrganizaionalUnit functions
#


def scan_deployed_ou(org_client, root_id):
    """
    Query AWS Organization for OrganizationalUnits.
    Returns a list of dictionary.
    """
    deployed_ou = []
    build_deployed_ou_table(org_client, 'root', root_id, deployed_ou)
    return deployed_ou


def build_deployed_ou_table(org_client, parent_name, parent_id, deployed_ou):
    """
    Recursively traverse deployed AWS Organization.  Build the 'deployed_ou'
    lookup table (list of dict).
    """
    children_ou = org_client.list_organizational_units_for_parent(
        ParentId=parent_id
    )['OrganizationalUnits']
    if not deployed_ou:
        deployed_ou.append(dict(
            Name = parent_name,
            Id = parent_id,
            Children = map(lambda ou: ou['Name'], children_ou),
        ))
    for ou in children_ou:
        ou['ParentId'] = parent_id
        deployed_ou.append(ou)
        build_deployed_ou_table(org_client, ou['Name'], ou['Id'], deployed_ou)


def children_in_ou_spec(ou_spec):
    """
    Check if if 'ou_spec' has any child OU.  Returns boolean.
    """
    if 'OU' in ou_spec and ou_spec['OU'] != None and len(ou_spec['OU']) != 0:
        return True
    return False


def create_ou (org_client, ou_name, parent_id):
    """
    Create new OrganizationalUnit ('ou_name') under specified parent
    OU ('parent_id')
    """
    return org_client.create_organizational_unit(
        ParentId=parent_id,
        Name=ou_name
    )['OrganizationalUnit']



def delete_ou (org_client, deployed_ou, ou_name):
    """
    Delete named OrganizaionalUnit from deployed AWS Organization.  Check if
    any children OU exist first.
    """
    if  lookup(deployed_ou, 'Name', ou_name, 'Children'):
        print "OU %s has children. Can not delete." % ou_name
    else:
        org_client.delete_organizational_unit (
            OrganizationalUnitId=lookup(deployed_ou, 'Name', ou_name, 'Id')
        )


def display_provissioned_ou (org_client, deployed_ou,
        parent_name, parent_id, indent):
    """
    Recursive function to display the deployed AWS Organization structure.
    """
    # query aws for child orgs
    child_ou_list = org_client.list_children(
        ParentId=parent_id,
        ChildType='ORGANIZATIONAL_UNIT'
    )['Children']
    # print parent ou name
    tab = '  '
    print tab*indent + parent_name + ':'
    # look for policies
    policy_names = list_policies_in_ou(org_client, parent_id)
    if len(policy_names) > 0:
        print tab*indent + tab + 'policies: ' + ', '.join(policy_names)
    # look for accounts
    account_list = list_accounts_in_ou(org_client, parent_id)
    if len(account_list) > 0:
        print tab*indent + tab + 'accounts: ' + ', '.join(account_list)
    # look for child OUs
    if len(child_ou_list ) > 0:
        print tab*indent + tab + 'child_ou:'
        indent+=2
        for ou in child_ou_list:
            # recurse
            ou_name = lookup(deployed_ou, 'Id', ou['Id'], 'Name')
            display_provissioned_ou(org_client, deployed_ou,
                    ou_name, ou['Id'], indent)


def manage_policy_attachments(org_client, args, deployed_policies, ou_spec, ou_id):
    """
    Attach or detach specified Service Control Policy ('ou_spec') to a
    deployed OrganizatinalUnit ('ou_id)'.
    """
    global change_counter
    # attach specified policies
    p_spec = get_policy_spec_for_ou(ou_spec)
    for policy_name in p_spec:
        policy_id = lookup(deployed_policies, 'Name', policy_name, 'Id')

        if not policy_attached(org_client, policy_id, ou_id) and not ensure_absent(ou_spec):
            change_counter += 1
            if not args.silent:
                print "attaching policy %s to OU %s" % (policy_name, ou_spec['Name'])
            if not args.dry_run:
                attach_policy(org_client, policy_id, ou_id)

    # detach unspecified policies
    policy_list = list_policies_in_ou(org_client, ou_id)
    for policy_name in policy_list:
        if policy_name not in p_spec and not ensure_absent(ou_spec):
            change_counter += 1
            policy_id = lookup(deployed_policies, 'Name', policy_name, 'Id')
            if not args.silent:
                print "detaching policy %s from OU %s" % (policy_name, ou_spec['Name'])
            if not args.dry_run:
                detach_policy(org_client, policy_id, ou_id)



def manage_ou (org_client, args, deployed_ou, deployed_policies, ou_spec_list, parent_name):
    """
    Recursive function to manage OrganizationalUnits in the AWS Organization.
    """
    global change_counter
    for ou_spec in ou_spec_list:

        # ou exists
        if lookup(deployed_ou, 'Name', ou_spec['Name']):
            if children_in_ou_spec(ou_spec):
                # recurse
                manage_ou(
                        org_client,
                        args,
                        deployed_ou,
                        deployed_policies,
                        ou_spec['OU'],
                        ou_spec['Name'])
            if ensure_absent(ou_spec):
                change_counter += 1
                if not args.silent:
                    print 'deleting OU', ou_spec['Name']
                if not args.dry_run:
                    delete_ou(org_client, deployed_ou, ou_spec['Name'])
            else:
                manage_policy_attachments(
                        org_client,
                        args,
                        deployed_policies,
                        ou_spec,
                        lookup(deployed_ou, 'Name', ou_spec['Name'], 'Id'))

        # ou does not exist
        elif not ensure_absent(ou_spec):
            change_counter += 1
            if not args.silent:
                print "creating new ou %s under parent %s" % (ou_spec['Name'], parent_name)
            if not args.dry_run:
                new_ou = create_ou( org_client, ou_spec['Name'],
                        lookup(deployed_ou, 'Name', parent_name, 'Id'))
                manage_policy_attachments( org_client, args, deployed_policies,
                        ou_spec, new_ou['Id'])
                if children_in_ou_spec(ou_spec) and isinstance(new_ou, dict) \
                        and 'Id' in new_ou:
                    # recurse
                    manage_ou( org_client, args, deployed_ou, deployed_policies,
                            ou_spec['OU'], new_ou['Name'])



#
# Main
#

def main():

    # get commandline args
    args = parse_args()

    # set up aws client for orgs
    org_client = boto3.client('organizations')

    # determine the Organization Root ID
    root_id = get_root_id(org_client)

    # initialize change counter
    global change_counter
    change_counter = 0

    # scan deployed resources in Organization
    deployed_policies = org_client.list_policies(
        Filter='SERVICE_CONTROL_POLICY'
    )['Policies']
    deployed_accounts = scan_deployed_accounts(org_client)
    deployed_ou = scan_deployed_ou(org_client, root_id)


    # run reporting
    if args.report_only:
        display_provissioned_policies(org_client, deployed_policies)
        display_provissioned_accounts(deployed_accounts)
        print
        print '_________________________________________'
        print 'Provissioned Organizational Units in Org:'
        display_provissioned_ou(org_client, deployed_ou, 'root', root_id, 0)


    # process organization spec-file
    else:
        # read org-spec yaml file into dictionary - initializes globals:
        #   org_spec
        #   default_policy
        #   master_account
        parse_org_specification(args)

        if args.dry_run: print "\nThis is a dry run!"

        if args.build_policy:
            manage_policies(org_client, args, deployed_policies,
                    org_spec['policy_spec'])
        if args.build_account:
            manage_accounts(org_client, args, deployed_accounts,
                    deployed_ou, org_spec['account_spec'])
        if args.build_ou:
            enable_policy_type_in_root(org_client, root_id)
            manage_ou( org_client, args, deployed_ou, deployed_policies,
                    org_spec['organizational_unit_spec'], 'root')

        # run follow-up report
        if not args.silent and not args.no_report:
            if change_counter > 0:
                # rescan deployed resources
                deployed_policies = org_client.list_policies(
                    Filter='SERVICE_CONTROL_POLICY'
                )['Policies']
                deployed_accounts = scan_deployed_accounts(org_client)
                deployed_ou = scan_deployed_ou(org_client, root_id)
            if args.build_policy:
                display_provissioned_policies(org_client, deployed_policies)
            if args.build_account:
                display_provissioned_accounts(deployed_accounts)
            if args.build_ou:
                print
                print '_________________________________________'
                print 'Provissioned Organizational Units in Org:'
                display_provissioned_ou(org_client, deployed_ou, 'root', root_id, 0)




# run it!
if __name__ == "__main__":
    main()


