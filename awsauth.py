#!/usr/bin/python


"""Manage users, group, and roles for cross account authentication in AWS.

Usage:
  awsauth report [--profile <profile>] [--verbose]
  awsauth create (--spec-file FILE) [--exec]
                  [--region <region>][--profile <profile>] [--verbose]
  awsauth provision (--spec-file FILE) (--template-dir DIR) [--exec]
                  [--region <region>][--profile <profile>] [--verbose]
  awsauth --version

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -r, --region <region>      AWS region to use when creating resources.
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
  -d DIR, --template-dir DIR  Directory where to search for cloudformation templates.
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
        scan_deployed_accounts,
        lookup,
        logger,
        ensure_absent)
import awsaccounts
from awsaccounts import get_assume_role_credentials



def validate_auth_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(spec_file).read())
    string_keys = ['auth_account_id', 'default_region']
    for key in string_keys:
        if not key in spec:
            msg = "Invalid spec-file: missing required param '%s'." % key
            raise RuntimeError(msg)
        if not isinstance(spec[key], str):
            msg = "Invalid spec-file: '%s' must be type 'str'." % key
            raise RuntimeError(msg)
    list_keys = ['users', 'groups']
    for key in list_keys:
        if not key in spec:
            msg = "Invalid spec-file: missing required param '%s'." % key
            raise RuntimeError(msg)
        if not isinstance(spec[key], list):
            msg = "Invalid spec-file: '%s' must be type 'list'." % key
            raise RuntimeError(msg)

    return spec


def validate_auth_account_id(session, spec):
    """
    Don't mangle the wrong account by accident
    """
    sts_client = session.client('sts')
    current_account_id = sts_client.get_caller_identity()['Account']
    if current_account_id != spec['auth_account_id']:
        errmsg = ("""The Account Id '%s' does not
          match the 'auth_account_id' set in the spec-file.  
          Is your '--profile' arg correct?""" % current_account_id)
        raise RuntimeError(errmsg)
    return


def scan_deployed_users(session):
    iam_client = session.client('iam')
    deployed_users = iam_client.list_users()['Users']
    return deployed_users


def scan_deployed_groups(session):
    iam_client = session.client('iam')
    deployed_groups = iam_client.list_groups()['Groups']
    return deployed_groups


def create_users(session, args, log, deployed, auth_spec):
    """
    Create IAM users based on user specification
    """
    iam_client = session.client('iam')
    for u_spec in auth_spec['users']:
        # ISSUE: does this belong in validate_spec()?
        if 'Path' in u_spec and u_spec['Path']:
            path = "/%s/" % u_spec['Path']
        else:
            path = '/'
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


def create_groups(session, args, log, deployed, auth_spec):
    """
    Create IAM groups based on group specification
    """
    iam_client = session.client('iam')
    for g_spec in auth_spec['groups']:
        # ISSUE: does this belong in validate_spec()?
        if 'Path' in g_spec and g_spec['Path']:
            path = "/%s/" % g_spec['Path']
        else:
            path = '/'
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


def manage_group_members(session, args, log, deployed, auth_spec):
    """
    Populate users into groups based on group specification.
    """
    iam_client = session.client('iam')
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
            #print current_members
            #print spec_members
            #print add_users
            #print remove_users
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


def create_policy(iam_client, args, logger, p_spec):
    # assume name and statement keys exist
    if 'Path' in p_spec and p_spec['Path']:
        path = "/%s/" % p_spec['Path']
    else:
        path = '/'
    if 'Description' in p_spec and p_spec['Description']:
        desc = p_spec['Description']
    else:
        desc = ''
    policy_doc = json.dumps(
            dict(Version='2012-10-17', Statement=p_spec['Statement']),
            indent=2, separators=(',', ': '))
    #print policy_doc
    response = iam_client.create_policy(
            PolicyName=p_spec['Name'],
            Path=path,
            PolicyDocument=policy_doc,
            Description=desc)

## Used for testing only
#def create_policies(session, args, log, deployed, auth_spec):
#    iam_client = session.client('iam')
#    for p_spec in auth_spec['policies']:
#        create_policy(iam_client, args, logger, p_spec)


#def create_delegation_role(iam_client, args, logger, deployed, d_spec):
#    principal = "arn:aws:iam::%s:root" % lookup(
#            deployed['accounts'], 'Name' ,d_spec['TrustingAccount'], 'Id')
#    statement = dict(
#            Effect=Allow,
#            Principal=dict(AWS=principal),
#            Action='sts:AssumeRole')
#    if 'MFA' in d_spec and d_spec['MFA'] == 'role':
#        statement['Condition'] = {'Bool':{'aws:MultiFactorAuthPresent':'true'}}
#    policy_doc = json.dumps(
#            dict(Version='2012-10-17', Statement=statement),
#            indent=2, separators=(',', ': '))
#    #print policy_doc
#    iam_client.create_role(
#            #Description=desc,
#            #Path=path,
#            RoleName=d_spec['RoleName'],
#            AssumeRolePolicyDocument=policy_doc)


def get_profile(args):
    if os.environ.get('AWS_PROFILE'):
        aws_profile = os.environ.get('AWS_PROFILE')
    elif args['--profile']:
        aws_profile = args['--profile']
    else:
        aws_profile = 'default'
    return aws_profile


def get_session(aws_profile):
    """
    Return boto3 session object for a given profile.  Try to 
    obtain client credentials from shell environment.  This should
    capture MFA credential if present in user's shell env.
    """
    return boto3.Session(
            profile_name=aws_profile,
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID', ''),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
            aws_session_token=os.environ.get('AWS_SESSION_TOKEN', ''))


def get_client_for_assumed_role(service_name, session, account_id, role):
    """
    Return boto3 client object for an assumed role
    """
    credentials = get_assume_role_credentials(session, account_id, role)
    return session.client(
            service_name,
            aws_access_key_id = credentials['AccessKeyId'],
            aws_secret_access_key = credentials['SecretAccessKey'],
            aws_session_token = credentials['SessionToken'])


def main():
    args = docopt(__doc__, version='awsorgs 0.0.0')
    aws_profile = get_profile(args)
    print aws_profile
    session = get_session(aws_profile)
    print session
    log = []
    deployed = dict(
            users = scan_deployed_users(session),
            groups = scan_deployed_groups(session))
    #print deployed['users']
    #print deployed['groups']

    if args['--spec-file']:
        auth_spec = validate_auth_spec_file(args['--spec-file'])
        validate_auth_account_id(session, auth_spec)
    #print auth_spec


    if args['create']:
        #create_users(session, args, log, deployed, auth_spec)
        #create_groups(session, args, log, deployed, auth_spec)
        #manage_group_members(session, args, log, deployed, auth_spec)
        ##create_policies(session, args, log, deployed, auth_spec)

        org_client = get_client_for_assumed_role(
                'organizations', session,
                auth_spec['master_account_id'],
                auth_spec['auth_access_role'])

        deployed['accounts'] = scan_deployed_accounts(org_client)
        print deployed['accounts']


    if args['--verbose']:
        for line in log:
            print line
     

if __name__ == "__main__":
    main()
