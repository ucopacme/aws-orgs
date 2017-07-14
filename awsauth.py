#!/usr/bin/python


"""Manage users, group, and roles for cross account authentication in AWS.

Usage:
  awsauth.py report [--profile <profile>] [--verbose]
  awsauth.py create (--spec-file FILE) [--exec]
                     [--region <region>][--profile <profile>] [--verbose]
  awsauth.py provision (--spec-file FILE) (--template-dir DIR) [--exec]
                     [--region <region>][--profile <profile>] [--verbose]
  awsauth.py --version

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

import yaml
#import time

import boto3
import botocore.exceptions
from botocore.exceptions import ClientError
import docopt
from docopt import docopt

import awsorgs
from awsorgs import (lookup, logger, ensure_absent)



def validate_auth_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(args['--spec-file']).read())
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
        user = lookup(deployed['users'], 'UserName', u_spec['Name'])
        if user:
            if ensure_absent(u_spec):
                logger(log, "deleting user '%s'" % u_spec['Name'])
                if args['--exec']:
                    iam_client.delete_user( UserName=u_spec['Name'])
                    logger(log, response['User']['Arn'])
            elif user['Path'] != "/%s/" % u_spec['Path']:
                logger(log, "updating path on user '%s'" % u_spec['Name'])
                if args['--exec']:
                    iam_client.update_user(
                            UserName=u_spec['Name'],
                            NewPath="/%s/" % u_spec['Path'])
        elif not ensure_absent(u_spec):
            logger(log, "creating user '%s'" % u_spec['Name'])
            if args['--exec']:
                response = iam_client.create_user(
                        UserName=u_spec['Name'],
                        Path="/%s/" % u_spec['Path'])
                logger(log, response['User']['Arn'])


def create_groups(session, args, log, deployed, auth_spec):
    """
    Create IAM groups based on group specification
    """
    iam_client = session.client('iam')
    for g_spec in auth_spec['groups']:
        group = lookup(deployed['groups'], 'GroupName', g_spec['Name'])
        if group:
            if ensure_absent(g_spec):
                # check if group has users
                if iam_client.get_group(GroupName=g_spec['Name'])['Users']:
                    logger(log,
                      "Warning: group '%s' still has users.  Can't delete." %
                      g_spec['Name'])
                else:
                    logger(log, "deleting group '%s'" % g_spec['Name'])
                    if args['--exec']:
                        iam_client.delete_group(GroupName=g_spec['Name'])
            elif group['Path'] != "/%s/" % g_spec['Path']:
                logger(log, "updating path on group '%s'" % g_spec['Name'])
                if args['--exec']:
                    iam_client.update_group(
                            GroupName=g_spec['Name'],
                            NewPath="/%s/" % g_spec['Path'])
        elif not ensure_absent(g_spec):
            logger(log, "creating group '%s'" % g_spec['Name'])
            if args['--exec']:
                response = iam_client.create_group(
                        GroupName=g_spec['Name'],
                        Path="/%s/" % g_spec['Path'])
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
            print current_members
            spec_members = [g_spec['Members'] for g_spec in [g_spec]
                    if 'Members' in g_spec]
            print spec_members
            add_users = [username for username in spec_members
                    if username not in current_members]
            remove_users = [username for username in current_members
                    if username not in spec_members]
            #if 'Members' in g_spec:
            #    spec_members = g_spec['Members']
            #else:
            #    spec_members = []
            for username in add_users:
                iam_client.add_user_to_group(
                    GroupName=g_spec['Name'],
                    UserName=username)
            for username in remove_users:
                iam_client.remove_user_from_group(
                    GroupName=g_spec['Name'],
                    UserName=username)





#
# Main
#
if __name__ == "__main__":
    args = docopt(__doc__, version='awsorgs 0.0.0')
    session = boto3.Session(profile_name=args['--profile'])
    log = []
    #print args
    deployed = dict(
      users = scan_deployed_users(session),
      groups = scan_deployed_groups(session),
    )
    #print deployed['users']
    #print deployed['groups']

    if args['--spec-file']:
        auth_spec = validate_auth_spec_file(args['--spec-file'])
        validate_auth_account_id(session, auth_spec)
        if args['--region']:
            auth_spec['region_name'] = args['--region']
        else:
            auth_spec['region_name'] = auth_spec['default_region']
    #print auth_spec


    if args['create']:
        create_users(session, args, log, deployed, auth_spec)
        create_groups(session, args, log, deployed, auth_spec)
        manage_group_members(session, args, log, deployed, auth_spec)


    if args['--verbose']:
        for line in log:
            print line
     
