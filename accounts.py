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
import time
from docopt import docopt
from awsorgs import (lookup, logger, get_root_id, ensure_absent,
    scan_deployed_accounts, validate_master_id)


"""
TODO:
DONE fill out validate_account_spec_file()
display_provisioned_accounts(): add option to print .aws/config file
"""


def validate_account_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(args['--spec-file']).read())
    string_keys = ['master_account_id', 'org_access_role']
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
            msg = (
                "%s: missing 'Name' key near: '%s'" %
                (err_prefix, str(a_spec))
            )
            raise RuntimeError(msg)

    # validate cloudformation_stacks spec
    err_prefix = "Malformed cloudformation spec in spec-file"
    for cf_spec in spec['cloudformation_stacks']:
        if not isinstance(cf_spec, dict):
            msg = "%s: not a dictionary: '%s'" % (err_prefix, str(cf_spec))
            raise RuntimeError(msg)
        if not 'Name' in cf_spec:
            msg = (
                "%s: missing 'Name' key near: '%s'" %
                (err_prefix, str(cf_spec))
            )
            raise RuntimeError(msg)
        if not ensure_absent(cf_spec):
            required_keys = ['Template', 'Tags']
            for key in required_keys:
                if not key in cf_spec:
                    msg = (
                        "%s: stack '%s': missing required param '%s'" %
                        (err_prefix, cf_spec['Name'], key)
                    )
                    raise RuntimeError(msg)
            list_keys = ['Capabilities', 'Parameters', 'Tags']
            for key in list_keys:
                if key in cf_spec and cf_spec[key]:
                    if not isinstance(cf_spec[key], list):
                        msg = (
                            "%s: stack '%s': value of '%s' must be a list." %
                            (err_prefix, cf_spec['Name'], key)
                        )
                        raise RuntimeError(msg)
    # all done!
    return spec


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


def create_stack(cf_client, args, log, account_name, stack_kwargs):
    """
    Create or update a cloudformation stack using change sets.
    """

    #print
    #print account_name
    # test if stack exists
    try:
        stack_status = cf_client.describe_stack_events(
            StackName=stack_kwargs['StackName']
        )['StackEvents'][0]['ResourceStatus']
        if stack_status == 'REVIEW_IN_PROGRESS':
            stack_kwargs['ChangeSetType'] = 'CREATE'
        else:
            stack_kwargs['ChangeSetType'] = 'UPDATE'
    except ClientError as e:
        if not e.response['Error']['Code'] == 'ValidationError':
            raise e
        else:
            stack_kwargs['ChangeSetType'] = 'CREATE'
    except:
        raise

    # create a change set
    stack_kwargs['ChangeSetName'] = stack_kwargs['StackName'] + '-changeset'
    cf_client.create_change_set(**stack_kwargs)

    # check its status. wash. and repeat.
    counter = 0
    while counter < 5:
        change_sets = cf_client.list_change_sets(
            StackName=stack_kwargs['StackName']
        )['Summaries']
        change_set = lookup(
            change_sets, 'ChangeSetName', stack_kwargs['ChangeSetName']
        )
        #print change_set['Status']
        #print change_set['ExecutionStatus']
        if change_set['Status'] == 'CREATE_PENDING':
            logger(log, "In progress.  wait a bit...")
            time.sleep(5)
        elif change_set['Status'] == 'FAILED':
            cf_client.delete_change_set(
                StackName=stack_kwargs['StackName'],
                ChangeSetName=stack_kwargs['ChangeSetName']
            )
            break
        elif (change_set['Status'] == 'CREATE_COMPLETE'
              and change_set['ExecutionStatus'] == 'AVAILABLE'):
            logger(
                log, "Notice: running %s stack '%s' in account '%s'." % (
                account_name, stack_kwargs['ChangeSetType'].lower(),
                stack_kwargs['StackName']
            ))
            if args['--exec']:
                cf_client.execute_change_set(
                    StackName=stack_kwargs['StackName'],
                    ChangeSetName=stack_kwargs['ChangeSetName']
                )
            break
        counter += 1


def provision_accounts(log, session, args, deployed_accounts, account_spec):
    """
    Generate default resources in new accounts using cloudformation.
    """
    for account in account_spec['accounts']:
        if 'Provision' in account and account['Provision']:
            account_id = lookup(
                deployed_accounts, 'Name', account['Name'], 'Id'
            )
            credentials = get_assume_role_credentials(
                session, account_id, account_spec['org_access_role']
            )
            cf_client = session.client(
                'cloudformation',
                aws_access_key_id = credentials['AccessKeyId'],
                aws_secret_access_key = credentials['SecretAccessKey'],
                aws_session_token = credentials['SessionToken'],
            )
            # build specified stacks
            for stack in account_spec['cloudformation_stacks']:
                template_file =  '/'.join([
                    args['--template-dir'], stack['Template']
                ])
                template_body = open(template_file).read()
                stack_kwargs = dict(
                    StackName=stack['Name'],
                    TemplateBody=template_body,
                    Capabilities=stack['Capabilities'],
                    Parameters=stack['Parameters'],
                    Tags=stack['Tags'],
                )
                create_stack(
                    cf_client, args, log, account['Name'], stack_kwargs
                )


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

