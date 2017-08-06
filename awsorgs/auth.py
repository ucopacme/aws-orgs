#!/usr/bin/python


"""Manage users, group, and roles for cross account authentication in an
AWS Organization.

Usage:
  awsauth report (--spec-file FILE) [-d] [--boto-log]
  awsauth users (--spec-file FILE) [--exec] [-vd] [--boto-log]
  awsauth delegation (--spec-file FILE) [--exec] [-vd] [--boto-log]
  awsauth --version
  awsauth --help

Modes of operation:
  report        Display provisioned resources (Implies '--verbose').
  users         Provision users, groups and group membership.
  delegation    Provision policies and roles for cross account access.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
  --exec                     Execute proposed changes to AWS accounts.
  -v, --verbose              Log to activity to STDOUT at log level INFO.
  -d, --debug                Increase log level to 'DEBUG'. Implies '--verbose'.
  --boto-log                 Include botocore and boto3 logs in log stream.

"""

import os
import sys
import yaml
import json

import boto3
import botocore.exceptions
from botocore.exceptions import ClientError
import docopt
from docopt import docopt

import awsorgs
from awsorgs import (
        lookup,
        ensure_absent,
        get_logger,
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


def validate_delegation_spec(args, log, d_spec):
    return True


def validate_policy_spec(args, log, p_spec):
    return True


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
    """
    Print report of currently deployed IAM users in Auth account.
    """
    header = "Provisioned IAM Users in Auth Account:"
    overbar = '_' * len(header)
    log.info("\n%s\n%s\n" % (overbar, header))
    for name in sorted([u['UserName'] for u in deployed['users']]):
        arn = lookup(deployed['users'], 'UserName', name, 'Arn')
        spacer = ' ' * (12 - len(name))
        log.info("%s%s\t%s" % (name, spacer, arn))


def display_provisioned_groups(credentials, log, deployed):
    """
    Print report of currently deployed IAM groups in Auth account.
    List group memebers, attached policies and delegation assume role
    profiles.
    """
    iam_resource = boto3.resource('iam', **credentials)
    header = "Provisioned IAM Groups in Auth Account:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for name in sorted(map(lambda g: g['GroupName'], deployed['groups'])):
        group = iam_resource.Group(name)
        members = list(group.users.all())
        attached_policies = list(group.attached_policies.all())
        assume_role_resources = [p.policy_document['Statement'][0]['Resource']
                for p in list(group.policies.all()) if
                p.policy_document['Statement'][0]['Action'] == 'sts:AssumeRole']
        log.info("\n%s\t%s" % ('Name:', name))
        log.info("%s\t%s" % ('Arn:', group.arn))
        if members:
            log.info("Members:")
            log.info("\n".join(["  %s" % u.name for u in members]))
        if attached_policies:
            log.info("Policies:")
            log.info("\n".join(["  %s" % p.arn for p in attached_policies]))
        if assume_role_resources:
            log.info("Assume role profiles:")
            log.info("  Account\tRole ARN")
            profiles = {}
            for role_arn in assume_role_resources:
                account_name = lookup(deployed['accounts'], 'Id',
                        role_arn.split(':')[4], 'Name')
                profiles[account_name] =  role_arn
            for account_name in sorted(profiles.keys()):
                log.info("  %s:\t%s" % (account_name, profiles[account_name]))


def display_roles_in_accounts(log, deployed, auth_spec):
    """
    Print report of currently deployed delegation roles in each account
    in the Organization.
    """
    header = "Provisioned IAM Roles in all Org Accounts:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for account in deployed['accounts']:
        credentials = get_assume_role_credentials( account['Id'],
                auth_spec['org_access_role'])
        iam_client = boto3.client('iam', **credentials)
        iam_resource = boto3.resource('iam', **credentials)
        role_names = [r['RoleName'] for r in iam_client.list_roles()['Roles']]
        custom_policies = iam_client.list_policies(Scope='Local')['Policies']
        log.info("\nAccount:\t%s" % account['Name'])
        if custom_policies:
            log.info("Custom Policies:")
            for policy in custom_policies:
                log.info("  %s" % policy['PolicyName'])
        log.info("Roles:")
        for name in role_names:
            role = iam_resource.Role(name)
            log.info("  %s" % name)
            log.info("    Arn:\t%s" % role.arn)
            log.info("    Principal:\t%s" % 
                    role.assume_role_policy_document['Statement'][0]['Principal']['AWS'])
            attached = [p.policy_name for p 
                     in list(role.attached_policies.all())]
            if attached:
                log.info("    Attached Policies:")
                for policy in attached:
                    log.info("      %s" % policy)


def create_users(iam_client, args, log, deployed, auth_spec):
    """
    Manage IAM users based on user specification
    """
    for u_spec in auth_spec['users']:
        path = munge_path(auth_spec['default_path'], u_spec)
        user = lookup(deployed['users'], 'UserName', u_spec['Name'])
        if user:
            if ensure_absent(u_spec):
                log.info("Deleting user '%s'" % u_spec['Name'])
                if args['--exec']:
                    iam_client.delete_user( UserName=u_spec['Name'])
                    log.info(response['User']['Arn'])
            elif user['Path'] != path:
                log.info("Updating path on user '%s'" % u_spec['Name'])
                if args['--exec']:
                    iam_client.update_user(
                            UserName=u_spec['Name'], NewPath=path)
        elif not ensure_absent(u_spec):
            log.info("Creating user '%s'" % u_spec['Name'])
            if args['--exec']:
                response = iam_client.create_user(
                        UserName=u_spec['Name'], Path=path)
                log.info(response['User']['Arn'])


def create_groups(iam_client, args, log, deployed, auth_spec):
    """
    Manage IAM groups based on group specification
    """
    for g_spec in auth_spec['groups']:
        path = munge_path(auth_spec['default_path'], g_spec)
        group = lookup(deployed['groups'], 'GroupName', g_spec['Name'])
        if group:
            if ensure_absent(g_spec):
                # check if group has users
                if iam_client.get_group(GroupName=g_spec['Name'])['Users']:
                    log.error("Group '%s' still has users.  "
                             "Can't delete." % g_spec['Name'])
                # delete group
                else:
                    log.info("Deleting group '%s'" % g_spec['Name'])
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
                log.info("Updating path on group '%s'" % g_spec['Name'])
                if args['--exec']:
                    iam_client.update_group(
                            GroupName=g_spec['Name'], NewPath=path)
        elif not ensure_absent(g_spec):
            # create group
            log.info("Creating group '%s'" % g_spec['Name'])
            if args['--exec']:
                response = iam_client.create_group(
                        GroupName=g_spec['Name'], Path=path)
                log.info(response['Group']['Arn'])


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
                    log.info("Adding user '%s' to group '%s'." %
                            (username, g_spec['Name']))
                    if args['--exec']:
                        iam_client.add_user_to_group(
                                GroupName=g_spec['Name'],
                                UserName=username)
                else:
                    log.error("User '%s' not found. Can not add user to "
                            "group '%s'" % (username, g_spec['Name']))
            for username in remove_users:
                log.info("Removig user '%s' from group '%s'." %
                        (username, g_spec['Name']))
                if args['--exec']:
                    iam_client.remove_user_from_group(
                            GroupName=g_spec['Name'],
                            UserName=username)


def manage_group_policies(credentials, args, log, deployed, auth_spec):
    """
    Attach managed policies to groups based on group specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    for g_spec in auth_spec['groups']:
        if ('Policies' in g_spec and g_spec['Policies']
                and not ensure_absent(g_spec)
                and lookup(deployed['groups'], 'GroupName', g_spec['Name'])):
            group = iam_resource.Group(g_spec['Name'])
            attached_policies = [p.policy_name for p
                    in list(group.attached_policies.all())]
            # attach missing policies
            for policy_name in g_spec['Policies']:
                if not policy_name in attached_policies:
                    policy_arn = get_policy_arn(iam_client, policy_name, args,
                            log, auth_spec)
                    log.info("Attaching policy '%s' to group '%s' in "
                            "account '%s'." % (policy_name, g_spec['Name'],
                            auth_spec['auth_account']))
                    if args['--exec']:
                        group.attach_policy(PolicyArn=policy_arn)
                elif lookup(auth_spec['custom_policies'], 'PolicyName',
                        policy_name):
                    policy_arn = get_policy_arn(iam_client, policy_name, args,
                            log, auth_spec)
            # datach obsolete policies
            for policy_name in attached_policies:
                if not policy_name in g_spec['Policies']:
                    policy_arn = get_policy_arn(iam_client, policy_name, args,
                            log, auth_spec)
                    log.info("Detaching policy '%s' from group '%s' in "
                            "account '%s'." % (policy_name, g_spec['Name'],
                            auth_spec['auth_account']))
                    if args['--exec']:
                        group.detach_policy(PolicyArn=policy_arn)


def get_policy_arn(iam_client, policy_name, args, log, auth_spec):
    """
    Return the policy arn of the named IAM policy in an account.
    Checks AWS scope first, then calls manage_custom_policy() for
    local scope policies.
    """
    aws_policies = iam_client.list_policies(Scope='AWS',
            MaxItems=500)['Policies']
    policy_arn = lookup(aws_policies, 'PolicyName', policy_name, 'Arn')
    if policy_arn:
        return policy_arn
    else:
        return manage_custom_policy(iam_client, policy_name, args,
                log, auth_spec)


def manage_custom_policy(iam_client, policy_name, args, log, auth_spec):
    """
    Create or update a custom IAM policy in an account based on
    a policy specification.  Returns the policy arn.
    """
    p_spec = lookup(auth_spec['custom_policies'], 'PolicyName', policy_name)
    if not p_spec:
        log.error("Custom Policy spec for '%s' not found in auth-spec." %
                policy_name)
        log.error("Policy creation failed.")
        return None
    if not validate_policy_spec(args, log, p_spec):
        log.error("Custom Policy spec for '%' invalid." % policy_name)
        log.error("Policy creation failed.")
        return None
    policy_doc = json.dumps(dict(
            Version='2012-10-17',
            Statement=p_spec['Statement']))
    custom_policies = iam_client.list_policies(Scope='Local')['Policies']
    policy = lookup(custom_policies, 'PolicyName', policy_name)
    if not policy:
        log.info("Creating custom policy '%s'." % policy_name)
        if args['--exec']:
            return iam_client.create_policy(
                PolicyName=p_spec['PolicyName'],
                Path=munge_path(auth_spec['default_path'], p_spec),
                Description=p_spec['Description'],
                PolicyDocument=policy_doc)['Policy']['Arn']
        return None
    else:
        current_doc = iam_client.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
                )['PolicyVersion']['Document']
        if json.dumps(current_doc) != policy_doc:
            log.info("Updating custom policy '%s'." % policy_name)
            if args['--exec']:
                iam_client.create_policy_version(
                        PolicyArn=policy['Arn'],
                        PolicyDocument=policy_doc,
                        SetAsDefault=True)
        return policy['Arn']


def set_group_assume_role_policies(d_spec, args, log, deployed, auth_spec):
    """
    Assign and manage assume role trust policies on IAM groups in
    Auth account.
    """
    credentials = get_assume_role_credentials(
            auth_spec['auth_account_id'],
            auth_spec['org_access_role'])
    iam_resource = boto3.resource('iam', **credentials)
    for trusting_account in d_spec['TrustingAccount']:

        # build group policies in trusted account
        group = iam_resource.Group(d_spec['TrustedGroup'])
        try:
            group.load()
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.error("Group '%s' not found in account '%s'." %
                        (d_spec['TrustedGroup'], d_spec['TrustedAccount']))
            else:
                log.info(e)
            return

        # assemble policy document for group policy
        trusting_account_id = lookup(deployed['accounts'], 'Name',
                trusting_account, 'Id')
        statement = dict(
                Effect='Allow',
                Action='sts:AssumeRole',
                Resource="arn:aws:iam::%s:role%s%s" % (
                        trusting_account_id,
                        munge_path(auth_spec['default_path'], d_spec),
                        d_spec['RoleName'])) 
        policy_doc = json.dumps(dict(
                Version='2012-10-17',
                Statement=[statement]))

        # manage group policy
        policy_name="%s-%s" % (d_spec['RoleName'], trusting_account_id)
        group_policies = [p.policy_name for p in list(group.policies.all())]
        if ensure_absent(d_spec): 
            if policy_name in group_policies:
                log.info("Deleting policy '%s' from group '%s' in "
                        "account '%s'." % (policy_name, d_spec['TrustedGroup'],
                        trusting_account))
                if args['--exec']:
                    group.Policy(policy_name).delete()
        else:
            if not policy_name in group_policies:
                log.info("Creating group policy '%s' for group '%s' in "
                        "account '%s'." % (policy_name, d_spec['TrustedGroup'],
                        auth_spec['auth_account']))
                if args['--exec']:
                    group.create_policy(
                            PolicyName=policy_name,
                            PolicyDocument=policy_doc)
            elif json.dumps(group.Policy(policy_name).policy_document) != policy_doc:
                log.info("Updating policy '%s' for group '%s' in "
                        "account '%s'." % (policy_name, d_spec['TrustedGroup'],
                        trusting_account))
                if args['--exec']:
                    group.Policy(policy_name).put(PolicyDocument=policy_doc)


def manage_delegation_role(credentials, args, log, deployed,
        auth_spec, account_name, d_spec):
    """
    Create and manage a cross account access delegetion role in an
    account based on delegetion specification.
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)

    # assemble assume role policy document for delegation role
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

    # get iam role object.  create delegation role if needed (i.e. won't load)
    role = iam_resource.Role(d_spec['RoleName'])
    try:
        role.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            if ensure_absent(d_spec):
                return
            else:
                log.info("Creating role '%s' in account '%s'." %
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

    if not ensure_absent(d_spec):
        # update delegation role if needed
        if json.dumps(role.assume_role_policy_document) != policy_doc:
            log.info("Updating policy document in role '%s' in account '%s'."
                    % (d_spec['RoleName'], account_name))
            if args['--exec']:
                iam_client.update_assume_role_policy(
                    RoleName=role.role_name,
                    PolicyDocument=policy_doc)
        if role.description != d_spec['Description']:
            log.info("Updating description in role '%s' in account '%s'." %
                    (d_spec['RoleName'], account_name))
            if args['--exec']:
                iam_client.update_role_description(
                    RoleName=role.role_name,
                    Description=d_spec['Description'])

        # manage policy attachments
        attached_policies = [p.policy_name for p
                in list(role.attached_policies.all())]
        for policy_name in d_spec['Policies']:
            # attach missing policies
            if not policy_name in attached_policies:
                policy_arn = get_policy_arn(iam_client, policy_name, args,
                        log, auth_spec)
                log.info("Attaching policy '%s' to role '%s' in account '%s'." %
                        (policy_name, d_spec['RoleName'], account_name))
                if args['--exec'] and policy_arn:
                    role.attach_policy(PolicyArn=policy_arn)
            elif lookup(auth_spec['custom_policies'], 'PolicyName',policy_name):
                policy_arn = get_policy_arn(iam_client, policy_name, args,
                        log, auth_spec)
        for policy_name in attached_policies:
            # datach obsolete policies
            if not policy_name in d_spec['Policies']:
                policy_arn = get_policy_arn(iam_client, policy_name, args,
                        log, auth_spec)
                log.info("Detaching policy '%s' from role '%s' in account '%s'."
                        % (policy_name, d_spec['RoleName'], account_name))
                if args['--exec'] and policy_arn:
                    role.detach_policy(PolicyArn=policy_arn)

    else:
        # delete delegation role
        log.info("Deleting role '%s' from account '%s'." %
                (d_spec['RoleName'], account_name))
        if args['--exec']:
            for p in list(role.attached_policies.all()):
                role.detach_policy(PolicyArn=p.arn)
            role.delete()


def manage_delegations(args, log, deployed, auth_spec):
    """
    Create and manage cross account access delegations based on 
    delegation specifications.  Manages delegation roles in 
    trusting accounts and group policies in Auth (trusted) account.
    """
    for d_spec in auth_spec['delegations']:
        if not validate_delegation_spec(args, log, d_spec):
            log.error("Delegation spec for '%s' invalid." % d_spec['RoleName'])
            log.error("Delegation creation failed.")
            return
        set_group_assume_role_policies(d_spec, args, log, deployed, auth_spec)
        for trusting_account in d_spec['TrustingAccount']:
            trusting_account_id = lookup(deployed['accounts'], 'Name',
                    trusting_account, 'Id')
            if not trusting_account_id:
                log.error("Cant find account %s" % trusting_account)
            else:
                credentials = get_assume_role_credentials(
                        trusting_account_id,
                        auth_spec['org_access_role'])
                manage_delegation_role(credentials, args, log,
                        deployed, auth_spec, trusting_account, d_spec)


def main():
    args = docopt(__doc__)
    log = get_logger(args)

    auth_spec = validate_auth_spec_file(args['--spec-file'])
    org_client = boto3.client('organizations')
    validate_master_id(org_client, auth_spec)
    credentials = get_assume_role_credentials(
            auth_spec['auth_account_id'],
            auth_spec['org_access_role'])
    iam_client = boto3.client('iam', **credentials)
    deployed = dict(
            users = iam_client.list_users()['Users'],
            groups = iam_client.list_groups()['Groups'],
            accounts = scan_deployed_accounts(org_client))

    if args['report']:
        display_provisioned_users(log, deployed)
        display_provisioned_groups(credentials, log, deployed)
        display_roles_in_accounts(log, deployed, auth_spec)

    if args['users']:
        create_users(iam_client, args, log, deployed, auth_spec)
        create_groups(iam_client, args, log, deployed, auth_spec)
        manage_group_members(iam_client, args, log, deployed, auth_spec)
        manage_group_policies(credentials, args, log, deployed, auth_spec)

    if args['delegation']:
        manage_delegations(args, log, deployed, auth_spec)

if __name__ == "__main__":
    main()
