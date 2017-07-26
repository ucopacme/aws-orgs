#!/usr/bin/python


"""Manage accounts in an AWS Organization.

Usage:
  awsaccounts report
  awsaccounts create (--spec-file FILE) [--exec] [--verbose]
  awsaccounts provision (--spec-file FILE) [--exec] [--verbose]
  awsaccounts (-h | --help)
  awsaccounts --version

Modes of operation:
  report         Display organization status report only.
  create         Create new accounts in AWS Org per specifation.
  provision      Manage default resources in Org accounts per specifation.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
  -d DIR, --template-dir DIR  Directory where to search for cloudformation templates.
  --exec                     Execute proposed changes to AWS accounts.
  -v, --verbose              Log activity to STDOUT.

"""


import yaml
import time

import boto3
import botocore.exceptions
from botocore.exceptions import ClientError
import docopt
from docopt import docopt

import awsorgs
import awsorgs.orgs
from awsorgs import (
        lookup,
        logger,
        ensure_absent,
        get_root_id,
        validate_master_id,
        get_resource_for_assumed_role,
        get_client_for_assumed_role)
from awsorgs.orgs import scan_deployed_accounts
from awsorgs.auth import munge_path, manage_delegation_role


def validate_account_spec_file(args):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(args['--spec-file']).read())
    string_keys = ['master_account_id', 'org_access_role', 'default_path']
    for key in string_keys:
        if not key in spec:
            msg = "Invalid spec-file: missing required param '%s'." % key
            raise RuntimeError(msg)
        if not isinstance(spec[key], str):
            msg = "Invalid spec-file: '%s' must be type 'str'." % key
            raise RuntimeError(msg)
    list_keys = ['cloudformation_stacks', 'accounts']
    for key in list_keys:
        if not key in spec:
            msg = "Invalid spec-file: missing required param '%s'." % key
            raise RuntimeError(msg)
        if not isinstance(spec[key], list):
            msg = "Invalid spec-file: '%s' must be type 'list'." % key
            raise RuntimeError(msg)

    # validate accounts spec
    err_prefix = "Malformed accounts spec in spec-file"
    for a_spec in spec['accounts']:
        if not isinstance(a_spec, dict):
            msg = "%s: not a dictionary: '%s'" % (err_prefix, str(a_spec))
            raise RuntimeError(msg)
        if not 'Name' in a_spec:
            msg = ("%s: missing 'Name' key near: '%s'" %
              (err_prefix, str(a_spec)))
            raise RuntimeError(msg)

    # validate cloudformation_stacks spec
    err_prefix = "Malformed cloudformation spec in spec-file"
    for cf_spec in spec['cloudformation_stacks']:
        if not isinstance(cf_spec, dict):
            msg = "%s: not a dictionary: '%s'" % (err_prefix, str(cf_spec))
            raise RuntimeError(msg)
        if not 'Name' in cf_spec:
            msg = ("%s: missing 'Name' key near: '%s'" %
                    (err_prefix, str(cf_spec)))
            raise RuntimeError(msg)
        if not ensure_absent(cf_spec):
            required_keys = ['Template', 'Tags']
            for key in required_keys:
                if not key in cf_spec:
                    msg = ("%s: stack '%s': missing required param '%s'" %
                            (err_prefix, cf_spec['Name'], key))
                    raise RuntimeError(msg)
            list_keys = ['Capabilities', 'Parameters', 'Tags']
            for key in list_keys:
                if key in cf_spec and cf_spec[key]:
                    if not isinstance(cf_spec[key], list):
                        msg = ("%s: stack '%s': value of '%s' must be a list." %
                                (err_prefix, cf_spec['Name'], key))
                        raise RuntimeError(msg)
    # all done!
    return spec


def scan_created_accounts(org_client):
    """
    Query AWS Organization for accounts with creation status of 'SUCCEEDED'.
    Returns a list of dictionary.
    """
    status = org_client.list_create_account_status(States=['SUCCEEDED'])
    created_accounts = status['CreateAccountStatuses']
    while 'NextToken' in status and status['NextToken']:
        status = org_client.list_create_account_status(States=['SUCCEEDED'],
                NextToken=status['NextToken'])
        created_accounts += status['CreateAccountStatuses']
    return created_accounts


def create_accounts(org_client, args, log, deployed_accounts, account_spec):
    """
    Compare deployed_accounts to list of accounts in the accounts spec.
    Create accounts not found in deployed_accounts.
    """
    for a_spec in account_spec['accounts']:
        if not lookup(deployed_accounts, 'Name', a_spec['Name'],):
            # check if it is still being provisioned
            created_accounts = scan_created_accounts(org_client)
            if lookup(created_accounts, 'AccountName', a_spec['Name']):
                logger(log, "New account '%s' is not yet available." %
                        a_spec['Name'])
                break
            # create a new account
            logger(log, "creating account '%s'" % (a_spec['Name']))
            if args['--exec']:
                new_account = org_client.create_account(
                        AccountName=a_spec['Name'], Email=a_spec['Email'])
                create_id = new_account['CreateAccountStatus']['Id']
                logger(log, "CreateAccountStatus Id: %s" % (create_id))
                # validate creation status
                counter = 0
                maxtries = 5
                while counter < maxtries:
                    creation = org_client.describe_create_account_status(
                            CreateAccountRequestId=create_id)['CreateAccountStatus']
                    if creation['State'] == 'IN_PROGRESS':
                        time.sleep(5)
                    elif creation['State'] == 'SUCCEEDED':
                        logger(log, "Account creation Succeeded!")
                        break
                    elif creation['State'] == 'FAILED':
                        logger(log, "Account creation failed! %s" %
                                creation['FailureReason'])
                        break
                    counter += 1
                if counter == maxtries and creation['State'] == 'IN_PROGRESS':
                     logger(log, "Account creation still pending. Moving on!")


def display_provisioned_accounts(log, deployed_accounts):
    """
    Print report of currently deployed accounts in AWS Organization.
    """
    header = "Provisioned Accounts in Org:"
    overbar = '_' * len(header)
    logger(log, "\n%s\n%s" % (overbar, header))
    for a_name in sorted(map(lambda a: a['Name'], deployed_accounts)):
        a_id = lookup(deployed_accounts, 'Name', a_name, 'Id')
        a_email = lookup(deployed_accounts, 'Name', a_name, 'Email')
        spacer = ' ' * (24 - len(a_name))
        logger(log, "%s%s%s\t\t%s" % (a_name, spacer, a_id, a_email))


def provision_accounts(org_client, log, args, deployed_accounts, account_spec):
    """
    Generate default resources in new accounts using cloudformation.
    """
    for a_spec in account_spec['accounts']:
        account_id = lookup(deployed_accounts, 'Name', a_spec['Name'], 'Id')
        if not account_id:
            # check if account is still being built
            created_accounts = scan_created_accounts(org_client)
            if lookup(created_accounts, 'AccountName', a_spec['Name']):
                logger(log,
                        "New account '%s' is not yet available." %
                        a_spec['Name'])
        else:
            if account_id == account_spec['master_account_id']:
                iam_client = boto3.client('iam')
                iam_resource = boto3.resource('iam')
            else:
                iam_client = get_client_for_assumed_role('iam',
                        account_id, account_spec['org_access_role'])
                iam_resource = get_resource_for_assumed_role('iam',
                        account_id, account_spec['org_access_role'])
            # create delegation
            for d_spec in account_spec['delegations']:
                manage_delegation_role(iam_client, iam_resource, args, log,
                        deployed_accounts, account_spec['default_path'],
                        a_spec['Name'], d_spec)


def main():
    args = docopt(__doc__, version='awsorgs 0.0.0')
    org_client = boto3.client('organizations')
    root_id = get_root_id(org_client)
    log = []
    deployed_accounts = scan_deployed_accounts(org_client)

    if args['--spec-file']:
        account_spec = validate_account_spec_file(args)
        validate_master_id(org_client, account_spec)

    if args['report']:
        args['--verbose'] = True
        display_provisioned_accounts(log, deployed_accounts)

    if args['create']:
        logger(log, "Running AWS account creation.")
        if not args['--exec']:
            logger(log, "This is a dry run!")
        create_accounts(org_client, args, log, deployed_accounts, account_spec)
        # check for unmanaged accounts
        unmanaged= [a
                for a in map(lambda a: a['Name'], deployed_accounts)
                if a not in map(lambda a: a['Name'], account_spec['accounts'])]
        if unmanaged:
            logger( log, "Warning: unmanaged accounts in Org: %s" %
                    (', '.join(unmanaged)))

    if args['provision']:
        logger(log, "Running AWS account provisioning.")
        if not args['--exec']:
            logger(log, "This is a dry run!")
        provision_accounts(org_client, log, args, deployed_accounts, account_spec)

    if args['--verbose']:
        for line in log:
            print line


if __name__ == "__main__":
    main()
