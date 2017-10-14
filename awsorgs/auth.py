#!/usr/bin/env python


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
  -V, --version              Display version info and exit.
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
import threading

import boto3
from botocore.exceptions import ClientError
from docopt import docopt

from awsorgs.utils import *


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
    # Thread worker function to assemble lines of a group report
    def display_group(group_name, report, iam_resource):
        log.debug('group_name: %s' % group_name)
        messages = []
        group = iam_resource.Group(group_name)
        members = list(group.users.all())
        attached_policies = list(group.attached_policies.all())
        assume_role_resources = [p.policy_document['Statement'][0]['Resource']
                for p in list(group.policies.all()) if
                p.policy_document['Statement'][0]['Action'] == 'sts:AssumeRole']
        messages.append("\n%s\t%s" % ('Name:', group_name))
        messages.append("%s\t%s" % ('Arn:', group.arn))
        if members:
            messages.append("Members:")
            messages.append("\n".join(["  %s" % u.name for u in members]))
        if attached_policies:
            messages.append("Policies:")
            messages.append("\n".join(["  %s" % p.arn for p in attached_policies]))
        if assume_role_resources:
            messages.append("Assume role profiles:")
            messages.append("  Account\tRole ARN")
            profiles = {}
            for role_arn in assume_role_resources:
                account_name = lookup(deployed['accounts'], 'Id',
                        role_arn.split(':')[4], 'Name')
                if account_name:
                    profiles[account_name] = role_arn
            for account_name in sorted(profiles.keys()):
                messages.append("  %s:\t%s" % (account_name, profiles[account_name]))
        report[group_name] = messages

    # gather report data from groups
    report = {}
    iam_resource = boto3.resource('iam', **credentials)
    group_names = sorted([g['GroupName'] for g in deployed['groups']])
    log.debug('group_names: %s' % group_names)
    queue_threads(log, group_names, display_group, f_args=(report, iam_resource),
            thread_count=10)

    # log report
    header = "Provisioned IAM Groups in Auth Account:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for group_name, messages in sorted(report.items()):
        for msg in messages:
            log.info(msg)


def display_roles_in_accounts(log, deployed, auth_spec):
    """
    Print report of currently deployed delegation roles in each account
    in the Organization.
    We only care about AWS principals, not Service principals.
    """
    # Thread worker function to gather report for each account
    def display_role(account, report, auth_spec):
        messages = []
        messages.append("\nAccount:\t%s" % account['Name'])
        credentials = get_assume_role_credentials(
                account['Id'],
                auth_spec['org_access_role'])
        if isinstance(credentials, RuntimeError):
            messages.append(credentials)
        else:
            iam_client = boto3.client('iam', **credentials)
            iam_resource = boto3.resource('iam', **credentials)
            role_names = [r['RoleName'] for r in iam_client.list_roles()['Roles']]
            custom_policies = iam_client.list_policies(Scope='Local')['Policies']
            if custom_policies:
                messages.append("Custom Policies:")
                for policy in custom_policies:
                    messages.append("  %s" % policy['PolicyName'])
            messages.append("Roles:")
            for name in role_names:
                role = iam_resource.Role(name)
                principal = role.assume_role_policy_document['Statement'][0]['Principal']
                if 'AWS' in principal:
                    messages.append("  %s" % name)
                    messages.append("    Arn:\t%s" % role.arn)
                    messages.append("    Principal:\t%s" % principal['AWS'])
                    attached = [p.policy_name for p in list(role.attached_policies.all())]
                    if attached:
                        messages.append("    Attached Policies:")
                        for policy in attached:
                            messages.append("      %s" % policy)
        report[account['Name']] = messages

    # gather report data from accounts
    report = {}
    queue_threads(log, deployed['accounts'], display_role, f_args=(report, auth_spec),
            thread_count=10)
    # process the reports
    header = "Provisioned IAM Roles in all Org Accounts:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for account, messages in sorted(report.items()):
        for msg in messages:
            log.info(msg)


# ISSUE: deleting user: may need to delete user policy and signing keys as well.
def create_users(credentials, args, log, deployed, auth_spec):
    """
    Manage IAM users based on user specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    for u_spec in auth_spec['users']:
        path = munge_path(auth_spec['default_path'], u_spec)
        deployed_user = lookup(deployed['users'], 'UserName', u_spec['Name'])
        if deployed_user:
            user = iam_resource.User(u_spec['Name'])
            # delete user
            if ensure_absent(u_spec):
                log.info("Deleting user '%s'" % u_spec['Name'])
                if args['--exec']:
                    for group in user.groups.all():
                        user.remove_group(GroupName=group.name)
                    for policy in user.attached_policies.all():
                        policy.detach_user(UserName=u_spec['Name'])
                    for key in user.access_keys.all():
                        key.delete()
                    for mfa in user.mfa_devices.all():
                        mfa.disassociate()
                    try:
                        user.LoginProfile().delete()
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchEntity':
                            pass
                    user.delete()
            # update user
            elif user.path != path:
                log.info("Updating path on user '%s'" % u_spec['Name'])
                if args['--exec']:
                    user.update(NewPath=path)
        # create new user
        elif not ensure_absent(u_spec):
            log.info("Creating user '%s'" % u_spec['Name'])
            if args['--exec']:
                response = iam_client.create_user(UserName=u_spec['Name'], Path=path)
                log.info(response['User']['Arn'])
                deployed['users'].append(response['User'])


def create_groups(credentials, args, log, deployed, auth_spec):
    """
    Manage IAM groups based on group specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    for g_spec in auth_spec['groups']:
        path = munge_path(auth_spec['default_path'], g_spec)
        deployed_group = lookup(deployed['groups'], 'GroupName', g_spec['Name'])
        if deployed_group:
            group = iam_resource.Group(g_spec['Name'])
            # delete group?
            if ensure_absent(g_spec):
                # check if group has users
                if list(group.users.all()):
                    log.error("Can not delete group '%s'. Still contains users"
                             % g_spec['Name'])
                else:
                    log.info("Deleting group '%s'" % g_spec['Name'])
                    if args['--exec']:
                        for policy in group.policies.all():
                            policy.delete()
                        for policy in group.attached_policies.all():
                            policy.detach_group(GroupName=g_spec['Name'])
                        group.delete()
                        deployed['groups'].remove(deployed_group)
            # update group?
            elif group.path != path:
                log.info("Updating path on group '%s'" % g_spec['Name'])
                if args['--exec']:
                    group.update(NewPath=path)
        # create group
        elif not ensure_absent(g_spec):
            log.info("Creating group '%s'" % g_spec['Name'])
            if args['--exec']:
                response = iam_client.create_group(
                        GroupName=g_spec['Name'], Path=path)
                log.info(response['Group']['Arn'])
                deployed['groups'].append(response['Group'])


def manage_group_members(credentials, args, log, deployed, auth_spec):
    """
    Populate users into groups based on group specification.
    """
    iam_resource = boto3.resource('iam', **credentials)
    for g_spec in auth_spec['groups']:
        if lookup(deployed['groups'], 'GroupName', g_spec['Name']):
            group = iam_resource.Group(g_spec['Name'])
            current_members = [user.name for user in group.users.all()] 
            # build list of specified group members
            spec_members = []
            if 'Members' in g_spec and g_spec['Members']:
                if g_spec['Members'] == 'ALL':
                    # all managed users except when user ensure: absent
                    spec_members = [user['Name'] for user in auth_spec['users']
                            if not ensure_absent(user)]
                    if 'ExcludeMembers' in g_spec and g_spec['ExcludeMembers']:
                        spec_members = [user for user in spec_members
                                if user not in g_spec['ExcludeMembers']]
                else:
                    # just specified members
                    for username in g_spec['Members']:
                        u_spec = lookup(auth_spec['users'], 'Name', username)
                        # not a managed user?
                        if not u_spec:
                            log.error("User '%s' not in auth_spec['users']. "
                                    "Can not add user to group '%s'" %
                                    (username, g_spec['Name']))
                        # managed but absent?
                        elif ensure_absent(u_spec):
                            log.error("User '%s' is specified 'absent' in "
                                    "auth_spec['users']. Can not add user "
                                    "to group '%s'" % 
                                    (username, g_spec['Name']))
                        else:
                            spec_members.append(username)
            # ensure all specified members are in group
            if not ensure_absent(g_spec):
                for username in spec_members:
                    if username not in current_members:
                        log.info("Adding user '%s' to group '%s'." %
                                (username, g_spec['Name']))
                        if args['--exec']:
                            group.add_user(UserName=username)
            # ensure no unspecified members are in group
            for username in current_members:
                if username not in spec_members:
                    log.info("Removing user '%s' from group '%s'." %
                            (username, g_spec['Name']))
                    if args['--exec']:
                        group.remove_user(UserName=username)


def manage_group_policies(credentials, args, log, deployed, auth_spec):
    """
    Attach managed policies to groups based on group specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    auth_account = lookup(deployed['accounts'], 'Id',
            auth_spec['auth_account_id'], 'Name')
    log.debug("auth account: '%s'" % auth_account)
    for g_spec in auth_spec['groups']:
        log.debug("processing group spec for '%s':\n%s" % (g_spec['Name'], g_spec))
        if 'Policies' in g_spec and g_spec['Policies']:
            if (lookup(deployed['groups'], 'GroupName', g_spec['Name'])
                    and not ensure_absent(g_spec)):
                group = iam_resource.Group(g_spec['Name'])
                attached_policies = [p.policy_name for p
                        in list(group.attached_policies.all())]
                log.debug("attached policies: '%s'" % attached_policies)
                log.debug("specified policies: '%s'" % g_spec['Policies'])
                # attach missing policies
                for policy_name in g_spec['Policies']:
                    if not policy_name in attached_policies:
                        policy_arn = get_policy_arn(iam_client, policy_name, args,
                                log, auth_spec)
                        log.debug("policy Arn for '%s': %s" % (policy_name, policy_arn))
                        log.info("Attaching policy '%s' to group '%s' in "
                                "account '%s'." % (policy_name, g_spec['Name'],
                                auth_account))
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
                                auth_account))
                        if args['--exec']:
                            group.detach_policy(PolicyArn=policy_arn)


def get_policy_arn(iam_client, policy_name, args, log, auth_spec):
    """
    Return the policy arn of the named IAM policy in an account.
    Checks AWS scope first, then calls manage_custom_policy() for
    local scope policies.
    """
    log.debug("policyName: '%s'" % policy_name)
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
    log.debug("policyName: '%s'" % policy_name)
    p_spec = lookup(auth_spec['custom_policies'], 'PolicyName', policy_name)
    if not p_spec:
        log.error("Custom Policy spec for '%s' not found in auth-spec." %
                policy_name)
        log.error("Policy creation failed.")
        return None
    policy_doc = json.dumps(dict(
            Version='2012-10-17',
            Statement=p_spec['Statement']))
    log.debug("Policy document from auth_spec:\n'%s'" %
            json.dumps(json.loads(policy_doc), indent=2, separators=(',', ': ')))
    custom_policies = iam_client.list_policies(Scope='Local')['Policies']
    log.debug("Custom policies:'%s'" % custom_policies)
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
        log.debug("Policy document from deployed policy:\n'%s'" %
                json.dumps(current_doc, indent=2, separators=(',', ': ')))
        if json.dumps(current_doc) != policy_doc:
            log.info("Updating custom policy '%s'." % policy_name)
            if args['--exec']:
                log.debug("check for non-default policy versions for '%s'" % policy_name)
                for v in iam_client.list_policy_versions(
                        PolicyArn=policy['Arn'])['Versions']:
                    if not v['IsDefaultVersion']:
                        log.info("Deleting non-default policy version '%s' for "
                                "policy '%s'" % (v['VersionId'], policy_name))
                        iam_client.delete_policy_version(
                                PolicyArn=policy['Arn'],
                                VersionId=v['VersionId'])
                iam_client.create_policy_version(
                        PolicyArn=policy['Arn'],
                        PolicyDocument=policy_doc,
                        SetAsDefault=True)
        return policy['Arn']


def set_group_assume_role_policies(args, log, deployed, auth_spec,
        trusting_accounts, d_spec):
    """
    Assign and manage assume role trust policies on IAM groups in
    Auth account.
    """
    log.debug('role: %s' % d_spec['RoleName'])
    credentials = get_assume_role_credentials(
            auth_spec['auth_account_id'],
            auth_spec['org_access_role'])
    iam_resource = boto3.resource('iam', **credentials)
    auth_account = lookup(deployed['accounts'], 'Id',
            auth_spec['auth_account_id'], 'Name')
    if lookup(deployed['groups'], 'GroupName', d_spec['TrustedGroup']):
        group = iam_resource.Group(d_spec['TrustedGroup'])
    else:
        log.error("Can not manage assume role policy for delegation role '%s' "
                "in group '%s'. Group not found in auth account '%s'" %
                (d_spec['RoleName'], d_spec['TrustedGroup'], auth_account))
        return

    # make list of existing group policies which match this role name
    group_policies_for_role = [p.policy_name for p in list(group.policies.all())
            if d_spec['RoleName'] in p.policy_name.split('-')]

    # test if delegation should be deleted
    if ensure_absent(d_spec): 
        for policy_name in group_policies_for_role:
            log.info("Deleting assume role group policy '%s' from group '%s' "
                    "in account '%s'" %
                    (policy_name, d_spec['TrustedGroup'], auth_account))
            if args['--exec']:
                group.Policy(policy_name).delete()
        return

    # keep track of managed group policies as we process them
    managed_policies = []
    for account in trusting_accounts:
        account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
        policy_name = "%s-%s" % (account, d_spec['RoleName'])
        managed_policies.append(policy_name)

        # assemble assume role policy document
        statement = dict(
                Effect='Allow',
                Action='sts:AssumeRole',
                Resource="arn:aws:iam::%s:role%s%s" % (
                        account_id,
                        munge_path(auth_spec['default_path'], d_spec),
                        d_spec['RoleName'])) 
        policy_doc = json.dumps(dict(
                Version='2012-10-17',
                Statement=[statement]))

        # create or update group policy
        if not policy_name in group_policies_for_role:
            log.info("Creating assume role policy '%s' for group '%s' in "
                    "account '%s'." % (policy_name, d_spec['TrustedGroup'],
                    auth_account))
            if args['--exec']:
                group.create_policy(
                        PolicyName=policy_name,
                        PolicyDocument=policy_doc)
        elif json.dumps(group.Policy(policy_name).policy_document) != policy_doc:
            log.info("Updating assume role policy '%s' for group '%s' in "
                    "account '%s'." % (policy_name, d_spec['TrustedGroup'],
                    auth_account))
            if args['--exec']:
                group.Policy(policy_name).put(PolicyDocument=policy_doc)

    # purge any policies for this role that are no longer being managed
    for policy_name in group_policies_for_role:
        if policy_name not in managed_policies:
            log.info("Deleting obsolete policy '%s' from group '%s' in "
                    "account '%s'." % (policy_name, d_spec['TrustedGroup'],
                    auth_account))
            if args['--exec']:
                group.Policy(policy_name).delete()


def manage_delegation_role(account, args, log, auth_spec, trusting_accounts, d_spec):
    """
    Create and manage a cross account access delegetion role in an
    account based on delegetion specification.
    """
    account_name = account['Name']
    log.debug('account: %s, role: %s' % (account_name, d_spec['RoleName']))
    credentials = get_assume_role_credentials(
            account['Id'],
            auth_spec['org_access_role'])
    if isinstance(credentials, RuntimeError):
        log.error(credentials)
        return
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    role = iam_resource.Role(d_spec['RoleName'])

    # check if role should not exist
    if account_name not in trusting_accounts or ensure_absent(d_spec):
        try:
            role.load()
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return
            else:
                raise e
        except:
            raise
        # delete delegation role
        log.info("Deleting role '%s' from account '%s'" %
                (d_spec['RoleName'], account_name))
        if args['--exec']:
            for p in list(role.attached_policies.all()):
                role.detach_policy(PolicyArn=p.arn)
            role.delete()
        return

    # else: assemble assume role policy document for delegation role
    principal = "arn:aws:iam::%s:root" % auth_spec['auth_account_id']
    statement = dict(
            Effect='Allow',
            Principal=dict(AWS=principal),
            Action='sts:AssumeRole')
    mfa = True
    if 'RequireMFA' in d_spec and d_spec['RequireMFA'] == False:
        mfa = False
    if mfa:
        statement['Condition'] = {
                'Bool':{'aws:MultiFactorAuthPresent':'true'}}
    policy_doc = json.dumps(dict(
            Version='2012-10-17', Statement=[statement]))

    # get iam role object.  create role if it does not exist (i.e. won't load)
    try:
        role.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            log.info("Creating role '%s' in account '%s'" %
                    (d_spec['RoleName'], account_name))
            if args['--exec']:
                iam_client.create_role(
                        Description=d_spec['Description'],
                        Path=munge_path(auth_spec['default_path'], d_spec),
                        RoleName=d_spec['RoleName'],
                        AssumeRolePolicyDocument=policy_doc)
                if 'Policies' in d_spec and d_spec['Policies']:
                    role.load()
                    for policy_name in d_spec['Policies']:
                        policy_arn = get_policy_arn(iam_client, policy_name,
                                args, log, auth_spec)
                        log.info("Attaching policy '%s' to role '%s' "
                                "in account '%s'" %
                                (policy_name, d_spec['RoleName'], account_name))
                        if args['--exec'] and policy_arn:
                            role.attach_policy(PolicyArn=policy_arn)
                return
            else:
                return
        else:
            raise e
    except:
        raise

    # update delegation role if needed
    if json.dumps(role.assume_role_policy_document) != policy_doc:
        log.info("Updating policy document in role '%s' in account '%s'" %
                (d_spec['RoleName'], account_name))
        if args['--exec']:
            iam_client.update_assume_role_policy(
                RoleName=role.role_name,
                PolicyDocument=policy_doc)
    if role.description != d_spec['Description']:
        log.info("Updating description in role '%s' in account '%s'" %
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
            log.info("Attaching policy '%s' to role '%s' in account '%s'" %
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
            log.info("Detaching policy '%s' from role '%s' in account '%s'" %
                    (policy_name, d_spec['RoleName'], account_name))
            if args['--exec'] and policy_arn:
                role.detach_policy(PolicyArn=policy_arn)


def manage_delegations(d_spec, args, log, deployed, auth_spec):
    """
    Create and manage cross account access delegations based on 
    delegation specifications.  Manages delegation roles in 
    trusting accounts and group policies in Auth (trusted) account.
    """
    log.debug('considering %s' % d_spec['RoleName'])
    if d_spec['RoleName'] == auth_spec['org_access_role']:
        log.error("Refusing to manage delegation '%s'" % d_spec['RoleName'])
        return

    # munge trusting_accounts list
    if d_spec['TrustingAccount'] == 'ALL':
        trusting_accounts = [a['Name'] for a in deployed['accounts']]
        if 'ExcludeAccounts' in d_spec and d_spec['ExcludeAccounts']:
            trusting_accounts = [a for a in trusting_accounts
                    if a not in d_spec['ExcludeAccounts']]
    else:
        trusting_accounts = d_spec['TrustingAccount']
    for account_name in trusting_accounts:
        if not lookup(deployed['accounts'], 'Name', account_name):
            log.error("Can not manage delegation role '%s' in account "
                    "'%s'.  Account '%s' not found in Organization" %
                    (d_spec['RoleName'], account_name, account_name))
            trusting_accounts.remove(account_name)

    # process groups in Auth account
    set_group_assume_role_policies(args, log, deployed, auth_spec,
            trusting_accounts, d_spec)

    # run manage_delegation_role() task in thread pool
    queue_threads(log, deployed['accounts'], manage_delegation_role,
            f_args=(args, log, auth_spec, trusting_accounts, d_spec))


def main():
    args = docopt(__doc__, version='0.0.6.rc1')
    log = get_logger(args)
    log.debug("%s: args:\n%s" % (__name__, args))
    auth_spec = validate_spec_file(log, args['--spec-file'], 'auth_spec')
    org_client = boto3.client('organizations')
    validate_master_id(org_client, auth_spec)
    credentials = get_assume_role_credentials(
            auth_spec['auth_account_id'],
            auth_spec['org_access_role'])
    iam_client = boto3.client('iam', **credentials)
    deployed = dict(
            users = iam_client.list_users()['Users'],
            groups = iam_client.list_groups()['Groups'],
            accounts = [a for a in scan_deployed_accounts(log, org_client)
                    if a['Status'] == 'ACTIVE'])

    if args['report']:
        display_provisioned_users(log, deployed)
        display_provisioned_groups(credentials, log, deployed)
        display_roles_in_accounts(log, deployed, auth_spec)

    if args['users']:
        create_users(credentials, args, log, deployed, auth_spec)
        create_groups(credentials, args, log, deployed, auth_spec)
        manage_group_members(credentials, args, log, deployed, auth_spec)
        manage_group_policies(credentials, args, log, deployed, auth_spec)

    if args['delegation']:
        queue_threads(log, auth_spec['delegations'], manage_delegations,
            f_args=(args, log, deployed, auth_spec))

if __name__ == "__main__":
    main()
