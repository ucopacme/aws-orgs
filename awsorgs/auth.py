#!/usr/bin/python


"""Manage users, group, and roles for cross account authentication in AWS.

Usage:
  awsauth report (--spec-file FILE)
  awsauth users (--spec-file FILE) [--exec] [--region <region>] [--verbose]
  awsauth delegation (--spec-file FILE) [--exec] [--region <region>] [--verbose]
  awsauth --version
  awsauth --help

Modes of operation:
  report        Display provisioned resources
  users         Provision users, groups and group membership
  delegation    Provision policies and roles for cross account access


Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
  --exec                     Execute proposed changes to AWS accounts.
  -v, --verbose              Log to STDOUT as well as log-target.

"""

import os
import yaml
import json
#import time

import boto3
import botocore.exceptions
from botocore.exceptions import ClientError
import docopt
from docopt import docopt

import awsorgs
from awsorgs import (
        lookup,
        logger,
        ensure_absent,
        get_resource_for_assumed_role,
        get_client_for_assumed_role)
from awsorgs.orgs import scan_deployed_accounts


def validate_auth_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(spec_file).read())
    string_keys = [
            'auth_account_id',
            'master_account_id',
            'auth_access_role',
            'default_group',
            'default_path']
    for key in string_keys:
        if not key in spec:
            msg = "Invalid spec-file: missing required param '%s'." % key
            raise RuntimeError(msg)
        if not isinstance(spec[key], str):
            msg = "Invalid spec-file: '%s' must be type 'str'." % key
            raise RuntimeError(msg)
    list_keys = ['users', 'groups', 'delegations', 'custom_policies']
    for key in list_keys:
        if not key in spec:
            msg = "Invalid spec-file: missing required param '%s'." % key
            raise RuntimeError(msg)
        if not isinstance(spec[key], list):
            msg = "Invalid spec-file: '%s' must be type 'list'." % key
            raise RuntimeError(msg)
    return spec


def validate_auth_account_id(spec):
    """
    Don't mangle the wrong account by accident
    """
    sts_client = boto3.client('sts')
    current_account_id = sts_client.get_caller_identity()['Account']
    if current_account_id != spec['auth_account_id']:
        errmsg = ("""The Account Id '%s' does not
              match the 'auth_account_id' set in the spec-file.  
              Is your AWS_PROFILE correct?""" % current_account_id)
        raise RuntimeError(errmsg)
    return


def munge_path(default_path, spec):
    """
    Return formated 'Path' attribute for use in iam client calls. 
    Prepend the 'default_path'.
    """
    if 'Path' in spec and spec['Path']:
        return "/%s/%s/" % (default_path, spec['Path'])
    return "/%s/" % default_path


def display_provisioned_users(log, deployed):
    header = "Provisioned IAM Users in Auth Account:"
    overbar = '_' * len(header)
    logger(log, "\n%s\n%s\n" % (overbar, header))
    for name in sorted(map(lambda u: u['UserName'], deployed['users'])):
        arn = lookup(deployed['users'], 'UserName', name, 'Arn')
        spacer = ' ' * (12 - len(name))
        logger(log, "%s%s\t%s" % (name, spacer, arn))


def display_provisioned_groups(iam_client, log, deployed):
    header = "Provisioned IAM Groups in Auth Account:"
    overbar = '_' * len(header)
    logger(log, "\n\n%s\n%s" % (overbar, header))
    for name in sorted(map(lambda g: g['GroupName'], deployed['groups'])):
        arn = lookup(deployed['groups'], 'GroupName', name, 'Arn')
        members = ["  %s" % user['UserName'] for user
                in iam_client.get_group( GroupName=name)['Users']
                if 'UserName' in user]
        logger(log, "\n%s\t%s" % ('Name:', name))
        logger(log, "%s\t%s" % ('Arn:', arn))
        logger(log, "Members:")
        logger(log, "\n".join(members))


def display_roles_in_accounts(args, log, deployed, auth_spec):
    header = "Provisioned IAM Roles in all Org Accounts:"
    overbar = '_' * len(header)
    logger(log, "\n\n%s\n%s" % (overbar, header))
    # Not working yet
    #for account in deployed['accounts']:
    # temp hack for testing
    for account in [lookup(deployed['accounts'], 'Name', 'test1'),
                    lookup(deployed['accounts'], 'Name', 'test2'),
                    ]:
        iam_client = get_client_for_assumed_role('iam',
             account['Id'], auth_spec['auth_access_role'])
        all_roles = iam_client.list_roles()['Roles']
        custom_policies = iam_client.list_policies(Scope='Local')['Policies']
        logger(log, "\nAccount:\t%s" % account['Name'])
        logger(log, "Roles:")
        for role in all_roles:
            logger(log, "  %s" % role['Arn'])
        logger(log, "Custom Policies:")
        for policy in custom_policies:
            logger(log, "  %s" % policy['Arn'])
        logger(log, '')


def create_users(args, log, deployed, auth_spec):
    """
    Create IAM users based on user specification
    """
    iam_client = boto3.client('iam')
    for u_spec in auth_spec['users']:
        path = munge_path(auth_spec['default_path'], u_spec)
        user = lookup(deployed['users'], 'UserName', u_spec['Name'])
        if user:
            if ensure_absent(u_spec):
                logger(log, "deleting user '%s'" % u_spec['Name'])
                if args['--exec']:
                    iam_client.delete_user( UserName=u_spec['Name'])
                    logger(log, response['User']['Arn'])
            elif user['Path'] != path:
                logger(log, "updating path on user '%s'" % u_spec['Name'])
                if args['--exec']:
                    iam_client.update_user(
                            UserName=u_spec['Name'], NewPath=path)
        elif not ensure_absent(u_spec):
            logger(log, "creating user '%s'" % u_spec['Name'])
            if args['--exec']:
                response = iam_client.create_user(
                        UserName=u_spec['Name'], Path=path)
                logger(log, response['User']['Arn'])


def create_groups(args, log, deployed, auth_spec):
    """
    Create IAM groups based on group specification
    """
    iam_client = boto3.client('iam')
    for g_spec in auth_spec['groups']:
        path = munge_path(auth_spec['default_path'], g_spec)
        group = lookup(deployed['groups'], 'GroupName', g_spec['Name'])
        if group:
            if ensure_absent(g_spec):
                # check if group has users
                if iam_client.get_group(GroupName=g_spec['Name'])['Users']:
                    logger(log,
                      "Warning: group '%s' still has users.  Can't delete." %
                      g_spec['Name'])
                # delete group
                else:
                    logger(log, "deleting group '%s'" % g_spec['Name'])
                    if args['--exec']:
                        iam_client.delete_group(GroupName=g_spec['Name'])
            elif group['Path'] != path:
                # update group
                logger(log, "updating path on group '%s'" % g_spec['Name'])
                if args['--exec']:
                    iam_client.update_group(
                            GroupName=g_spec['Name'], NewPath=path)
        elif not ensure_absent(g_spec):
            # create group
            logger(log, "creating group '%s'" % g_spec['Name'])
            if args['--exec']:
                response = iam_client.create_group(
                        GroupName=g_spec['Name'], Path=path)
                logger(log, response['Group']['Arn'])


def manage_group_members(args, log, deployed, auth_spec):
    """
    Populate users into groups based on group specification.
    """
    iam_client = boto3.client('iam')
    for g_spec in auth_spec['groups']:
        if (lookup(deployed['groups'], 'GroupName', g_spec['Name'])
                and not ensure_absent(g_spec)):
            response = iam_client.get_group(
                    GroupName=g_spec['Name'])['Users']
            current_members = [user['UserName'] for user in response
                    if 'UserName' in user]
            if 'Members' in g_spec and g_spec['Members']:
                spec_members = g_spec['Members']
            else:
                spec_members = []
            add_users = [username for username in spec_members
                    if username not in current_members]
            remove_users = [username for username in current_members
                    if username not in spec_members]
            for username in add_users:
                if lookup(deployed['users'], 'UserName', username):
                    logger(log, "Adding user '%s' to group '%s'." %
                            (username, g_spec['Name']))
                    if args['--exec']:
                        iam_client.add_user_to_group(
                                GroupName=g_spec['Name'],
                                UserName=username)
            for username in remove_users:
                logger(log, "Removig user '%s' from group '%s'." %
                        (username, g_spec['Name']))
                if args['--exec']:
                    iam_client.remove_user_from_group(
                            GroupName=g_spec['Name'],
                            UserName=username)


#def create_policy(iam_client, args, log, auth_spec p_spec):
#    """
#    under construction
#    """
#    # assume name and statement keys exist
#    path = munge_path(auth_spec['default_path'], p_spec)
#    if 'Path' in p_spec and p_spec['Path']:
#        path = "/%s/" % p_spec['Path']
#    else:
#        path = '/'
#    if 'Description' in p_spec and p_spec['Description']:
#        desc = p_spec['Description']
#    else:
#        desc = ''
#    policy_doc = json.dumps(
#            dict(Version='2012-10-17', Statement=p_spec['Statement']),
#            indent=2, separators=(',', ': '))
#    #print policy_doc
#    response = iam_client.create_policy(
#            PolicyName=p_spec['Name'],
#            Path=path,
#            PolicyDocument=policy_doc,
#            Description=desc)

## Used for testing only
#def create_policies(args, log, deployed, auth_spec):
#    iam_client = boto3.client('iam')
#    for p_spec in auth_spec['policies']:
#        create_policy(iam_client, args, log, p_spec)


def manage_delegation_role(iam_client, iam_resource, args, log,
        deployed, default_path, account_name, d_spec):
    """
    use mfa by default
    """
    # generate policy document
    trusted_account_id = lookup(deployed['accounts'], 'Name',
            d_spec['TrustedAccount'], 'Id')
    principal = "arn:aws:iam::%s:root" % trusted_account_id
    statement = dict(
            Effect='Allow',
            Principal=dict(AWS=principal),
            Action='sts:AssumeRole')
    mfa = True
    if 'RequireMFA' in d_spec and d_spec['RequireMFA'] == False:
        mfa = False
    if mfa:
        statement['Condition'] = {'Bool':{'aws:MultiFactorAuthPresent':'true'}}
    policy_doc = json.dumps(dict(Version='2012-10-17', Statement=[statement]))

    # create role object
    role = iam_resource.Role(d_spec['RoleName'])
    try:
        role.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            logger(log, "Creating role '%s' in account '%s'." %
                    (d_spec['RoleName'], account_name))
            if args['--exec']:
                iam_client.create_role(
                        Description=d_spec['Description'],
                        Path=munge_path(auth_spec['default_path'], d_spec),
                        RoleName=d_spec['RoleName'],
                        AssumeRolePolicyDocument=policy_doc)
    try:
        role.reload()
    except:
        raise

    # update role
    print json.dumps(role.assume_role_policy_document)
    print policy_doc
    #print role.description
    #print role.name
    #print role.role_name
    if json.dumps(role.assume_role_policy_document) != policy_doc:
        logger(log, "Updating policy document in role '%s' in account '%s'." %
                (d_spec['RoleName'], account_name))
        if args['--exec']:
            iam_client.update_assume_role_policy(
                RoleName=role.role_name,
                PolicyDocument=policy_doc)
    if role.description != d_spec['Description']:
        logger(log, "Updating description in role '%s' in account '%s'." %
                (d_spec['RoleName'], account_name))
        if args['--exec']:
            iam_client.update_role_description(
                RoleName=role.role_name,
                Description=d_spec['Description'])
    #print role.assume_role_policy_document
    #print role.description

    # manage policy attachments
    all_policies = iam_client.list_policies()['Policies']
    attached_policies = [p.policy_name for p
            in list(role.attached_policies.all())]
    #print attached_policies
    # attach missing policies
    for policy_name in d_spec['Policies']:
        #print policy_name
        policy_arn = lookup(all_policies, 'PolicyName', policy_name, 'Arn')
        #print policy_arn
        if not policy_name in attached_policies and policy_arn:
            logger(log, "Attaching policy '%s' to role '%s' in account '%s'." %
                    (policy_name, d_spec['RoleName'], account_name))
            if args['--exec']:
                role.attach_policy(PolicyArn=policy_arn)
    # datach obsolete policies
    for policy_name in attached_policies:
        #print policy_name
        policy_arn = lookup(all_policies, 'PolicyName', policy_name, 'Arn')
        #print policy_arn
        if not policy_name in d_spec['Policies']:
            logger(log,"Detaching policy '%s' from role '%s' in account '%s'." %
                    (policy_name, d_spec['RoleName'], account_name))
            if args['--exec']:
                role.detach_policy(PolicyArn=policy_arn)
        # check if policy still attached to any other roles
        policy = iam_resource.Policy(policy_arn)
        if policy.attachment_count == '0':
            logger(log, "Deleting custom policy '%s' from account '%s'." %
                    (policy_name, account_name))
            if args['--exec']:
                policy.delete()

            
            
def create_custom_policy(iam_client, args, log, policy_name, auth_spec):
    p_spec = lookup(auth_spec['custom_policies'], 'PolicyName', policy_name) 
    #print p_spec
    if not p_spec:
        logger(log, "Custom Policy spec for '%s' not found in auth-spec." %
                policy_name)
        logger(log, "Policy creation failed.")
        return
    if not validate_policy_spec(args, log, p_spec):
        logger(log, "Policy spec for '%' invalid." % policy_name)
        logger(log, "Policy creation failed.")
        return
    policy_doc = json.dumps(
            dict(Version='2012-10-17', Statement=p_spec['Statement']),
            indent=2, separators=(',', ': '))
    #print policy_doc
    if args['--exec']:
        iam_client.create_policy(
            PolicyName=p_spec['PolicyName'],
            Path=munge_path(auth_spec['default_path'], p_spec),
            Description=p_spec['Description'],
            PolicyDocument=policy_doc)




def validate_policy_spec(args, log, p_spec):
    return True





def manage_delegations(args, log, deployed, auth_spec):

    for d_spec in auth_spec['delegations']:
        #print d_spec

        for trusting_account in d_spec['TrustingAccount']:
            print trusting_account
            trusting_account_id = lookup(deployed['accounts'], 'Name',
                    trusting_account, 'Id')
            iam_client = get_client_for_assumed_role('iam',
                    trusting_account_id, auth_spec['auth_access_role'])
            iam_resource = get_resource_for_assumed_role('iam',
                    trusting_account_id, auth_spec['auth_access_role'])
            # create custom policies in trusting account
            for policy_name in d_spec['Policies']:
                #print policy_name
                all_policies = iam_client.list_policies()['Policies']
                if not lookup(all_policies, 'PolicyName', policy_name):
                    logger(log, "Creating custom policy '%s' in account '%s'." %
                            (policy_name, d_spec['TrustingAccount']))
                    create_custom_policy(iam_client, args, log,
                            policy_name, auth_spec)
            # manage role
            manage_delegation_role(iam_client, iam_resource, args, log,
                    deployed, auth_spec['default_path'], trusting_account,
                    d_spec)
            # create group sts.assume role policies
            # in progress


def main():
    args = docopt(__doc__, version='awsorgs 0.0.0')
    log = []
    iam_client = boto3.client('iam')
    deployed = dict(
            users = iam_client.list_users()['Users'],
            groups = iam_client.list_groups()['Groups'])
    #print deployed['users']
    #print deployed['groups']
    #print

    auth_spec = validate_auth_spec_file(args['--spec-file'])
    validate_auth_account_id(auth_spec)
    org_client = get_client_for_assumed_role('organizations',
            auth_spec['master_account_id'],
            auth_spec['auth_access_role'])
    deployed['accounts'] = scan_deployed_accounts(org_client)

    if args['report']:
        args['--verbose'] = True
        display_provisioned_users(log, deployed)
        display_provisioned_groups(iam_client, log, deployed)
        display_roles_in_accounts(args, log, deployed, auth_spec)


    if args['users']:
        create_users(args, log, deployed, auth_spec)
        create_groups(args, log, deployed, auth_spec)
        manage_group_members(args, log, deployed, auth_spec)

    if args['delegation']:
        #print deployed['accounts']
        manage_delegations(args, log, deployed, auth_spec)

        ## # testing only:
        ##create_policies(args, log, deployed, auth_spec)

    if args['--verbose']:
        for line in log:
            print line
     

if __name__ == "__main__":
    main()
