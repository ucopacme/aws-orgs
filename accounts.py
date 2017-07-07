#!/usr/bin/python


"""Manage accounts in an AWS Organization.

Usage:
  accounts.py report [--profile <profile>] [--verbose]
                     [--log-target <target>]...
  accounts.py create (--spec-file FILE) [--exec] [--profile <profile>]
                     [--verbose] [--log-target <target>]...
  accounts.py provision (--spec-file FILE) (--template-dir DIR) [--exec]
                     [--profile <profile>] [--verbose]
                     [--log-target <target>]...
  accounts.py (-h | --help)
  accounts.py --version

Modes of operation:
  report         Display organization status report only.
  create         Create new accounts in AWS Org per specifation.
  provision      Manage default resources in Org accounts per specifation.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
  -d DIR, --template-dir DIR  Directory where to search for cloudformation templates.
  --exec                     Execute proposed changes to AWS accounts.
  -l, --log-target <target>  Where to send log output.  This option can be
                             repeated to specify multiple targets.
  -v, --verbose              Log to STDOUT as well as log-target.

Supported log targets:
  local file:       /var/log/orgs.out
  email addresses:  agould@blee.red
  AWS sns stream:   ??syntax??
  

"""


import boto3
from botocore.exceptions import ClientError
import yaml
from docopt import docopt
from awsorgs import (lookup, logger, get_root_id, scan_deployed_accounts,
    validate_master_id)


"""
TODO:
fill out validate_account_spec_file()
display_provisioned_accounts(): add option to print .aws/config file
"""


def validate_account_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    account_spec = yaml.load(open(args['--spec-file']).read())
    return account_spec


def scan_created_accounts(org_client):
    """
    Query AWS Organization for accounts with creation status of 'SUCCEEDED'.
    Returns a list of dictionary.
    """
    status = org_client.list_create_account_status(
            States=['SUCCEEDED'])
    created_accounts = status['CreateAccountStatuses']
    while 'NextToken' in status and status['NextToken']:
        status = org_client.list_create_account_status(
                States=['SUCCEEDED'],
                NextToken=status['NextToken'])
        created_accounts += status['CreateAccountStatuses']
    return created_accounts


def create_accounts(org_client, args, log, deployed_accounts, account_spec):
    """
    Compare deployed_accounts to list of accounts in the accounts spec.
    Create accounts not found in deployed_accounts.
    """
    import time
    for a_spec in account_spec['accounts']:
        if not lookup(deployed_accounts, 'Name', a_spec['Name'],):

            # check if it is still being provisioned
            created_accounts = scan_created_accounts(org_client)
            if lookup(created_accounts, 'AccountName', a_spec['Name']):
                logger(log, "Account '%s' created, but not fully provisioned" %
                        a_spec['Name'])
                return lookup(created_accounts, 'AccountName', a_spec['Name'],
                        'AccountId')

            # create a new account
            logger(log, "creating account '%s'" % (a_spec['Name']))
            if args['--exec']:
                new_account = org_client.create_account(
                        AccountName=a_spec['Name'], Email=a_spec['Email'])
                create_id = new_account['CreateAccountStatus']['Id']
                logger(log, "CreateAccountStatus Id: %s" % (create_id))

                # validate creation status
                counter = 0
                while counter < 5:
                    logger(log, "Testing account creation status")
                    creation = org_client.describe_create_account_status(
                            CreateAccountRequestId=create_id
                            )['CreateAccountStatus']
                    if creation['State'] == 'IN_PROGRESS':
                        logger(log, "In progress.  wait a bit...")
                        time.sleep(5)
                    elif creation['State'] == 'SUCCEEDED':
                        logger(log, "Account creation Succeeded!")
                        return creation['Id']
                    elif creation['State'] == 'FAILED':
                        logger(log, "Account creation failed! %s" %
                                creation['FailureReason'])
                        return None
                    counter += 1



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
        spacer = ' ' * (16 - len(a_name))
        logger(log, "%s%s%s\t\t%s" % (a_name, spacer, a_id, a_email))


def get_assume_role_credentials(session, account_id, role_name):
            """
            Get temporary sts assume_role credentials for account.
            """
            role_arn = 'arn:aws:iam::' + account_id + ':role/' + role_name
            role_session_name = account_id + '-' + role_name
            sts_client = session.client('sts')
            credentials = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=role_session_name,
            )['Credentials']
            return credentials


def provision_accounts(log, session, args, deployed_accounts, account_spec):
    """
    Generate default resources in new accounts using cloudformation.
    """
    for account in account_spec['accounts']:
        if 'Provision' in account and account['Provision']:
            account_id = lookup(
                deployed_accounts,'Name',account['Name'],'Id'
            )
            credentials = get_assume_role_credentials(
                session, account_id, account_spec['org_access_role']
            )

            # apply temp creds to cloudformantion client
            cf_client = session.client(
                'cloudformation',
                aws_access_key_id = credentials['AccessKeyId'],
                aws_secret_access_key = credentials['SecretAccessKey'],
                aws_session_token = credentials['SessionToken'],
            )
            # build specified stacks
            for stack in account_spec['cloudformation']['stacks']:
                template_body = open(
                    '/'.join([args['--template-dir'], stack['template']])
                ).read()
                #kwargs = (
                #    StackName=stack['name'],
                #    TemplateBody=template_body,
                #    Capabilities=stack['capabilities'],
                #    Parameters=stack['parameters'],
                #    Tags=stack['tags'],
                #)
                try:
                    #response = cf_client.create_stack(kwargs)
                    response = cf_client.create_stack(
                        StackName=stack['name'],
                        TemplateBody=template_body,
                        Capabilities=stack['capabilities'],
                        Parameters=stack['parameters'],
                        Tags=stack['tags'],
                    )
                    logger(
                        log, "Notice: account %s: created stack %s." %
                        (account['Name'], stack['name'])
                    )
                except ClientError as e:
                    # probably I want to just ignore this error
                    if e.response['Error']['Code'] == 'AlreadyExistsException':
                        logger(
                            log, "Notice: account %s: stack %s exists." % 
                            (account['Name'], stack['name'])
                        )
                        try:
                            response = cf_client.update_stack(
                                StackName=stack['name'],
                                TemplateBody=template_body,
                                Capabilities=stack['capabilities'],
                                Parameters=stack['parameters'],
                                Tags=stack['tags'],
                            )
                        except ClientError as e:
                            if e.response['Error']['Code'] == 'ValidationError':
                                logger(
                                    log, "Notice: account %s: stack %s: %s" % (
                                    account['Name'], stack['name'],
                                    e.response['Error']['Message']
                                ))
                            else: raise e
                    else: raise e






#
# Main
#
if __name__ == "__main__":
    args = docopt(__doc__, version='awsorgs 0.0.0')
    session = boto3.Session(profile_name=args['--profile'])
    org_client = session.client('organizations')
    root_id = get_root_id(org_client)
    log = []
    deployed_accounts = scan_deployed_accounts(org_client)


    if args['--spec-file']:
        account_spec = validate_account_spec_file(args['--spec-file'])
        validate_master_id(org_client, account_spec)


    if args['report']:
        display_provisioned_accounts(log, deployed_accounts)


    if args['create']:
        logger(log, "Running AWS account creation.")
        if not args['--exec']:
            logger(log, "This is a dry run!\n")
        create_accounts(org_client, args, log, deployed_accounts, account_spec)

        # check for unmanaged accounts
        unmanaged= [
            a for a in map(lambda a: a['Name'], deployed_accounts)
            if a not in map(lambda a: a['Name'], account_spec['accounts'])
        ]
        if unmanaged:
            logger(
                log, "Warning: unmanaged accounts in Org: %s" %
                (', '.join(unmanaged))
            )


    if args['provision']:
        logger(log, "Running AWS account provisioning.")
        if not args['--exec']:
            logger(log, "This is a dry run!\n")
        provision_accounts(log, session, args, deployed_accounts, account_spec)


    if args['--verbose']:
        for line in log:
            print line

