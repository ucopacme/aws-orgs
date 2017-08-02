#!/usr/bin/python


"""Manage users, group, and roles for cross account authentication in AWS.

Usage:
  awsauth report (--spec-file FILE)
  awsauth users (--spec-file FILE) [--exec] [--verbose]
  awsauth delegation (--spec-file FILE) [--exec] [--verbose]
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
        validate_master_id,
)
from awsorgs.orgs import scan_deployed_accounts


def validate_auth_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(spec_file).read())
    string_keys = [
            'master_account_id',
            'auth_account_id',
            'auth_account',
            'org_access_role',
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


def munge_path(default_path, spec):
    """
    Return formated 'Path' attribute for use in iam client calls. 
    Prepend the 'default_path'.
    """
    if 'Path' in spec and spec['Path']:
        return "/%s/%s/" % (default_path, spec['Path'])
    return "/%s/" % default_path


def get_assume_role_credentials(account_id, role_name, path=None,
        region_name=None):
    """
    Get temporary sts assume_role credentials for account.
    """
    if path:
        role_arn = "arn:aws:iam::%s:role/%s/%s" % ( account_id, path, role_name)
    else:
        role_arn = "arn:aws:iam::%s:role/%s" % ( account_id, role_name)
    role_session_name = account_id + '-' + role_name
    sts_client = boto3.client('sts')

    if account_id == sts_client.get_caller_identity()['Account']:
        return dict(
                aws_access_key_id=None,
                aws_secret_access_key=None,
                aws_session_token=None,
                region_name=None)
    else:
        credentials = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=role_session_name
                )['Credentials']
        return dict(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region_name)


def display_provisioned_users(log, deployed):
    header = "Provisioned IAM Users in Auth Account:"
    overbar = '_' * len(header)
    logger(log, "\n%s\n%s\n" % (overbar, header))
    for name in sorted([u['UserName'] for u in deployed['users']]):
        arn = lookup(deployed['users'], 'UserName', name, 'Arn')
        spacer = ' ' * (12 - len(name))
        logger(log, "%s%s\t%s" % (name, spacer, arn))


def display_provisioned_groups(iam_client, log, deployed):
    header = "Provisioned IAM Groups in Auth Account:"
    overbar = '_' * len(header)
    logger(log, "\n\n%s\n%s" % (overbar, header))
    for name in sorted(map(lambda g: g['GroupName'], deployed['groups'])):
        arn = lookup(deployed['groups'], 'GroupName', name, 'Arn')
        members = iam_client.get_group(GroupName=name)['Users']
        group_policies = iam_client.list_group_policies(
                GroupName=name)['PolicyNames']
        assume_role_profiles = []
        for policy_name in group_policies:
            doc = iam_client.get_group_policy( GroupName=name,
                    PolicyName=policy_name)['PolicyDocument']
            if doc['Statement'][0]['Action'] == 'sts:AssumeRole':
                assume_role_profiles.append(doc['Statement'][0]['Resource'])
        logger(log, "\n%s\t%s" % ('Name:', name))
        logger(log, "%s\t%s" % ('Arn:', arn))
        logger(log, "Members:")
        logger(log, "\n".join(["  %s" % user['UserName'] for user in members]))
        logger(log, "Policies:")
        logger(log, "\n".join(["  %s" % p for p in group_policies]))
        logger(log, "Assume role profiles:")
        logger(log, "\n".join(["  %s" % p for p in assume_role_profiles]))


def display_roles_in_accounts(args, log, deployed, auth_spec):
    header = "Provisioned IAM Roles in all Org Accounts:"
    overbar = '_' * len(header)
    logger(log, "\n\n%s\n%s" % (overbar, header))
    for account in deployed['accounts']:
        credentials = get_assume_role_credentials( account['Id'],
                auth_spec['org_access_role'])
        iam_client = boto3.client('iam', **credentials)
        iam_resource = boto3.resource('iam', **credentials)
        role_names = [r['RoleName'] for r in iam_client.list_roles()['Roles']]
        custom_policies = iam_client.list_policies(Scope='Local')['Policies']
        logger(log, "\nAccount:\t%s" % account['Name'])
        logger(log, "Roles:")
        for name in role_names:
            role = iam_resource.Role(name)
            logger(log, "  Arn:\t\t%s" % role.arn)
            logger(log, "  Principal:\t%s" % 
                    role.assume_role_policy_document['Statement'][0]['Principal']['AWS'])
            logger(log, "  Policies:\t%s" % ' '.join(
                    [p.policy_name for p 
                     in list(role.attached_policies.all())]))
        logger(log, "Custom Policies:")
        for policy in custom_policies:
            logger(log, "  %s" % policy['PolicyName'])
        logger(log, '')


def create_users(iam_client, args, log, deployed, auth_spec):
    """
    Create IAM users based on user specification
    """
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


def create_groups(iam_client, args, log, deployed, auth_spec):
    """
    Create IAM groups based on group specification
    """
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
                        # delete group policies
                        for policy_name in iam_client.list_group_policies(
                                GroupName=g_spec['Name'])['PolicyNames']:
                            iam_client.delete_group_policy(
                                    GroupName=g_spec['Name'],
                                    PolicyName=policy_name)
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


# ISSUE: slightly easier using an iam resource instead of iam_client
def manage_group_members(iam_client, args, log, deployed, auth_spec):
    """
    Populate users into groups based on group specification.
    """
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


def set_group_assume_role_policies(d_spec, args, log, deployed, auth_spec):

    credentials = get_assume_role_credentials(
            auth_spec['auth_account_id'],
            auth_spec['org_access_role'])
    iam_resource = boto3.resource('iam', **credentials)
    for trusting_account in d_spec['TrustingAccount']:
        print trusting_account

        # build group policies in trusted account
        print d_spec['TrustedGroup']
        group = iam_resource.Group(d_spec['TrustedGroup'])
        try:
            group.load()
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger(log, "Group '%s' not found in account '%s'." %
                        (d_spec['TrustedGroup'], d_spec['TrustedAccount']))
            else:
                logger(log, e)
            return

        # assemble policy document for group policy
        trusting_account_id = lookup(deployed['accounts'], 'Name',
                trusting_account, 'Id')
        statement = dict(
                Effect='Allow',
                Action='sts:AssumeRole',
                #Resource="arn:aws:iam::%s:role/%s" % (trusting_account_id,
                #         d_spec['RoleName']))
                Resource="arn:aws:iam::%s:role%s%s" % (
                        trusting_account_id,
                        munge_path(auth_spec['default_path'], d_spec),
                        d_spec['RoleName'])) 
        policy_doc = json.dumps(dict(
                Version='2012-10-17',
                Statement=[statement]))

        # manage group policy
        policy_name="%s-%s" % (d_spec['RoleName'], trusting_account_id)
        print policy_name
        group_policies = [p.policy_name for p in list(group.policies.all())]
        if ensure_absent(d_spec): 
            if policy_name in group_policies:
                logger(log,
                        "Deleting policy '%s' from group '%s' in account '%s'."
                        % (policy_name, d_spec['TrustedGroup'], trusting_account))
                if args['--exec']:
                    group.Policy(policy_name).delete()
        else:
            if not policy_name in group_policies:
                logger(log,
                        "Creating group policy '%s' for group '%s' in account '%s'."
                        % (policy_name, d_spec['TrustedGroup'], auth_spec['auth_account']))
                if args['--exec']:
                    group.create_policy(
                            PolicyName=policy_name,
                            PolicyDocument=policy_doc)
            elif json.dumps(group.Policy(policy_name).policy_document) != policy_doc:
                logger(log,
                        "Updating policy '%s' for group '%s' in account '%s'."
                        % (policy_name, d_spec['TrustedGroup'], trusting_account))
                if args['--exec']:
                    group.Policy(policy_name).put(PolicyDocument=policy_doc)


def manage_delegation_role(credentials, args, log, deployed,
        auth_spec, account_name, d_spec):
    """
    use mfa by default
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    # assemble assume role policy document for delegation role
    print d_spec['RoleName']
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

    # create role if it doesn't yet exist
    role = iam_resource.Role(d_spec['RoleName'])
    try:
        role.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            if ensure_absent(d_spec):
                return
            else:
                logger(log, "Creating role '%s' in account '%s'." %
                        (d_spec['RoleName'], account_name))
                if args['--exec']:
                    iam_client.create_role(
                            Description=d_spec['Description'],
                            Path=munge_path(auth_spec['default_path'], d_spec),
                            RoleName=d_spec['RoleName'],
                            AssumeRolePolicyDocument=policy_doc)
                    if 'Policies' in d_spec and d_spec['Policies']:
                        role.load()
                        attach_role_policies(iam_client, args, log,
                                account_name, role, d_spec)
                    return
                else:
                    return

    # check ensure status
    if ensure_absent(d_spec):
        logger(log, "Deleting role '%s' from account '%s'." %
                (d_spec['RoleName'], account_name))
        if args['--exec']:
            for p in list(role.attached_policies.all()):
                role.detach_policy(PolicyArn=p.arn)
            role.delete()
    else:
        # update delegation role if needed
        if json.dumps(role.assume_role_policy_document) != policy_doc:
            logger(log, "Updating policy document in role '%s' in account '%s'."                    % (d_spec['RoleName'], account_name))
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
        # manage policy attachments
        attach_role_policies(iam_client, args, log, account_name, role, d_spec)


def attach_role_policies(iam_client, args, log, account_name, role, d_spec):
    # manage policy attachments
    all_policies = iam_client.list_policies()['Policies']
    attached_policies = [p.policy_name for p
            in list(role.attached_policies.all())]
    # attach missing policies
    for policy_name in d_spec['Policies']:
        policy_arn = lookup(all_policies, 'PolicyName', policy_name, 'Arn')
        if not policy_name in attached_policies and policy_arn:
            logger(log,
                    "Attaching policy '%s' to role '%s' in account '%s'."
                    % (policy_name, d_spec['RoleName'], account_name))
            if args['--exec']:
                role.attach_policy(PolicyArn=policy_arn)
    # datach obsolete policies
    for policy_name in attached_policies:
        policy_arn = lookup(all_policies, 'PolicyName', policy_name, 'Arn')
        if not policy_name in d_spec['Policies']:
            logger(log,
                    "Detaching policy '%s' from role '%s' in account '%s'."
                    % (policy_name, d_spec['RoleName'], account_name))
            if args['--exec']:
                role.detach_policy(PolicyArn=policy_arn)

            
def create_custom_policy(credentials, args, log, policy_name, auth_spec):
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
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



def validate_delegation_spec(args, log, d_spec):
    return True


def validate_policy_spec(args, log, p_spec):
    return True


def manage_delegations(args, log, deployed, auth_spec):
    for d_spec in auth_spec['delegations']:
        if not validate_delegation_spec(args, log, d_spec):
            logger(log, "Delegation spec for '%' invalid." % d_spec['RoleName'])
            logger(log, "Delegation creation failed.")
            return
        set_group_assume_role_policies(d_spec, args, log, deployed, auth_spec)

        # manage delegation roles/policies in trusting accounts
        for trusting_account in d_spec['TrustingAccount']:
            print trusting_account
            trusting_account_id = lookup(deployed['accounts'], 'Name',
                    trusting_account, 'Id')
            if not trusting_account_id:
                logger(log, "Cant find account %s" % trusting_account)
            else:
                credentials = get_assume_role_credentials(
                        trusting_account_id,
                        auth_spec['org_access_role'])

                # check for custom policies in trusting account
                #TODO: check for policy updates
                for policy_name in d_spec['Policies']:
                    #manage_custom_policy(...)
                    iam_client = boto3.client('iam', **credentials)
                    all_policies = iam_client.list_policies()['Policies']
                    if not lookup(all_policies, 'PolicyName', policy_name):
                        logger(log,
                                "Creating custom policy '%s' in account '%s'." %
                                (policy_name, d_spec['TrustingAccount']))
                        create_custom_policy(credentials, args, log,
                                policy_name, auth_spec)

                # manage role in trusting account
                manage_delegation_role(credentials, args, log,
                        deployed, auth_spec, trusting_account, d_spec)


def main():
    args = docopt(__doc__, version='awsorgs 0.0.0')
    log = []
    deployed = {}
    auth_spec = validate_auth_spec_file(args['--spec-file'])
    org_client = boto3.client('organizations')
    validate_master_id(org_client, auth_spec)
    credentials = get_assume_role_credentials(
            auth_spec['auth_account_id'],
            auth_spec['org_access_role'])
    iam_client = boto3.client('iam', **credentials)
    deployed['users'] = iam_client.list_users()['Users']
    deployed['groups'] = iam_client.list_groups()['Groups']
    deployed['accounts'] = scan_deployed_accounts(org_client)

    if args['report']:
        args['--verbose'] = True
        display_provisioned_users(log, deployed)
        display_provisioned_groups(iam_client, log, deployed)
        display_roles_in_accounts(args, log, deployed, auth_spec)

    if args['users']:
        create_users(iam_client, args, log, deployed, auth_spec)
        create_groups(iam_client, args, log, deployed, auth_spec)
        manage_group_members(iam_client, args, log, deployed, auth_spec)

    if args['delegation']:
        manage_delegations(args, log, deployed, auth_spec)

    if args['--verbose']:
        for line in log:
            print line
     

if __name__ == "__main__":
    main()
