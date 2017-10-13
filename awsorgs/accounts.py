#!/usr/bin/env python


"""Manage accounts in an AWS Organization.

Usage:
  awsaccounts report [-d] [--role ROLENAME] [--boto-log]
  awsaccounts create (--spec-file FILE) [--exec] [-vd] [--boto-log]
  awsaccounts alias (--spec-file FILE) [--role ROLENAME] [--exec] [-vd] [--boto-log]
  awsaccounts invite (--account-id ID --spec-file FILE)
                     [--exec] [-vd] [--boto-log]
  awsaccounts (-h | --help)
  awsaccounts --version

Modes of operation:
  report         Display organization status report only.
  create         Create new accounts in AWS Org per specifation.
  alias          Set account alias for each account in Org per specifation.
  invite         Invite another account to join Org as a member account. 

Options:
  -h, --help                 Show this help message and exit.
  -V, --version              Display version info and exit.
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
  --account-id ID            Id of account being invited to join Org.
  --exec                     Execute proposed changes to AWS accounts.
  --role ROLENAME            IAM role to use to access accounts.
                             [default: OrganizationAccountAccessRole]
  -v, --verbose              Log to activity to STDOUT at log level INFO.
  -d, --debug                Increase log level to 'DEBUG'. Implies '--verbose'.
  --boto-log                 Include botocore and boto3 logs in log stream.

"""


import yaml
import time

import boto3
import botocore
from botocore.exceptions import ClientError
from docopt import docopt
#botocore.errorfactory.EntityAlreadyExistsException 

from awsorgs.utils import *
from awsorgs.orgs import scan_deployed_accounts


def scan_created_accounts(log, org_client):
    """
    Query AWS Organization for accounts with creation status of 'SUCCEEDED'.
    Returns a list of dictionary.
    """
    log.debug('running')
    status = org_client.list_create_account_status(States=['SUCCEEDED'])
    created_accounts = status['CreateAccountStatuses']
    while 'NextToken' in status and status['NextToken']:
        log.debug("NextToken: %s" % status['NextToken'])
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
            created_accounts = scan_created_accounts(log, org_client)
            if lookup(created_accounts, 'AccountName', a_spec['Name']):
                log.warn("New account '%s' is not yet available" %
                        a_spec['Name'])
                break
            # create a new account
            if 'Email' in a_spec and a_spec['Email']:
                email_addr = a_spec['Email']
            else:
                email_addr = '%s@%s' % (a_spec['Name'], account_spec['default_domain'])
            log.info("Creating account '%s'" % (a_spec['Name']))
            log.debug('account email: %s' % email_addr)
            if args['--exec']:
                new_account = org_client.create_account(
                        AccountName=a_spec['Name'], Email=email_addr)
                create_id = new_account['CreateAccountStatus']['Id']
                log.info("CreateAccountStatus Id: %s" % (create_id))
                # validate creation status
                counter = 0
                maxtries = 5
                while counter < maxtries:
                    creation = org_client.describe_create_account_status(
                            CreateAccountRequestId=create_id
                            )['CreateAccountStatus']
                    if creation['State'] == 'IN_PROGRESS':
                        time.sleep(5)
                        log.info("Account creation in progress for '%s'" %
                                a_spec['Name'])
                    elif creation['State'] == 'SUCCEEDED':
                        log.info("Account creation succeeded")
                        break
                    elif creation['State'] == 'FAILED':
                        log.error("Account creation failed: %s" %
                                creation['FailureReason'])
                        break
                    counter += 1
                if counter == maxtries and creation['State'] == 'IN_PROGRESS':
                     log.warn("Account creation still pending. Moving on!")


def set_account_alias(account, log, args, account_spec):
    """
    Set an alias on an account.  Use 'Alias' attribute from account spec
    if provided.  Otherwise set the alias to the account name.
    """
    if account['Status'] == 'ACTIVE':
        a_spec = lookup(account_spec['accounts'], 'Name', account['Name'])
        if a_spec and 'Alias' in a_spec:
            proposed_alias = a_spec['Alias']
        else:
            proposed_alias = account['Name'].lower()
        credentials = get_assume_role_credentials(account['Id'], args['--role'])
        if isinstance(credentials, RuntimeError):
            log.error(credentials)
        else:
            iam_client = boto3.client('iam', **credentials)
        aliases = iam_client.list_account_aliases()['AccountAliases']
        log.debug('account_name: %s; aliases: %s' % (account['Name'], aliases))
        if not aliases:
            log.info("setting account alias to '%s' for account '%s'" %
                    (proposed_alias, account['Name']))
            if args['--exec']:
                try:
                    iam_client.create_account_alias(AccountAlias=proposed_alias)
                except Exception as e:
                    log.error(e)
        elif aliases[0] != proposed_alias:
            log.info("resetting account alias for account '%s' to '%s'; "
                    "previous alias was '%s'" %
                    (account['Name'], proposed_alias, aliases[0]))
            if args['--exec']:
                iam_client.delete_account_alias(AccountAlias=aliases[0])
                try:
                    iam_client.create_account_alias(AccountAlias=proposed_alias)
                except Exception as e:
                    log.error(e)
        

def get_account_aliases(log, args, deployed_accounts):
    """
    Return dict of {account_name:account_alias}
    """
    # worker function for threading
    def get_account_alias(account, log, args, aliases):
        if account['Status'] == 'ACTIVE':
            credentials = get_assume_role_credentials(account['Id'], args['--role'])
            if isinstance(credentials, RuntimeError):
                log.error(credentials)
            else:
                iam_client = boto3.client('iam', **credentials)
            aliases[account['Name']] = iam_client.list_account_aliases()['AccountAliases'][0]
    # call workers
    aliases = {}
    queue_threads(log, deployed_accounts, get_account_alias,
            f_args=(log, args, aliases), thread_count=10)
    log.debug(aliases)
    return aliases


def scan_invited_accounts(log, org_client):
    """Return a list of handshake IDs"""
    handshakes = org_client.list_handshakes_for_organization(
            Filter={'ActionType': 'INVITE'})['Handshakes']
    log.debug(handshakes)
    return handshakes


def invite_account(log, args, org_client, deployed_accounts):
    """Invite account_id to join Org"""
    account_id = args['--account-id']
    if lookup(deployed_accounts, 'Id', account_id):
        log.error("account %s already in organization" % account_id)
    invited_account_ids = [lookup(invite['Parties'], 'Type', 'ACCOUNT', 'Id')
            for invite in scan_invited_accounts(log, org_client)]
    log.debug('invited_account_ids: %s' % invited_account_ids)
    if account_id in invited_account_ids:
        log.error("account %s already in organization" % account_id)
        return
    log.info("inviting account %s to join Org" % account_id)
    if args['--exec']:
        target = dict(Id=account_id , Type='ACCOUNT')
        handshake = org_client.invite_account_to_organization(Target=target)['Handshake']
        log.info('account invite handshake Id: %s' % handshake['Id'])
        return handshake
    return


def display_invited_accounts(log, org_client):
    invited_accounts = scan_invited_accounts(log, org_client)
    if invited_accounts:
        header = "Invited Accounts in Org:"
        overbar = '_' * len(header)
        log.info("\n%s\n%s\n" % (overbar, header))
        fmt_str = "{:16}{:12}{}"
        log.info(fmt_str.format('Id:', 'State:', 'Expires:'))
        for invite in invited_accounts:
            account_id = lookup(invite['Parties'], 'Type', 'ACCOUNT', 'Id')
            invite_state = invite['State']
            invite_expiration = invite['ExpirationTimestamp']
            log.info(fmt_str.format(account_id, invite_state, invite_expiration))


def display_provisioned_accounts(log, deployed_accounts, aliases, status):
    """
    Print report of currently deployed accounts in AWS Organization.
    status::    matches account status (ACTIVE|SUSPENDED)
    """
    if status not in ('ACTIVE', 'SUSPENDED'):
        log.critical("'status' must be one of ('ACTIVE', 'SUSPENDED')")
        sys.exit(1)
    account_list = sorted([a['Name'] for a in deployed_accounts
            if a['Status'] == status])
    if account_list:
        header = '%s Accounts in Org:' % status.capitalize()
        overbar = '_' * len(header)
        log.info("\n%s\n%s\n" % (overbar, header))
        fmt_str = "{:20}{:20}{:16}{}"
        log.info(fmt_str.format('Name:', 'Alias', 'Id:', 'Email:'))
        for a_name in account_list:
            a_alias = aliases.get(a_name, '')
            a_id = lookup(deployed_accounts, 'Name', a_name, 'Id')
            a_email = lookup(deployed_accounts, 'Name', a_name, 'Email')
            log.info(fmt_str.format(a_name, a_alias, a_id, a_email))


def unmanaged_accounts(log, deployed_accounts, account_spec):
    deployed_account_names = [a['Name'] for a in deployed_accounts] 
    spec_account_names = [a['Name'] for a in account_spec['accounts']]
    log.debug('deployed_account_names: %s' % deployed_account_names)
    log.debug('spec_account_names: %s' % spec_account_names)
    return [a for a in deployed_account_names if a not in spec_account_names]


def main():
    args = docopt(__doc__, version='0.0.6.rc1')
    log = get_logger(args)
    log.debug(args)
    org_client = boto3.client('organizations')
    root_id = get_root_id(org_client)
    deployed_accounts = scan_deployed_accounts(log, org_client)

    if args['--spec-file']:
        account_spec = validate_spec_file(log, args['--spec-file'], 'account_spec')
        validate_master_id(org_client, account_spec)

    if args['report']:
        aliases = get_account_aliases(log, args, deployed_accounts)
        display_provisioned_accounts(log, deployed_accounts, aliases, 'ACTIVE')
        display_provisioned_accounts(log, deployed_accounts, aliases, 'SUSPENDED')
        display_invited_accounts(log, org_client)

    if args['create']:
        create_accounts(org_client, args, log, deployed_accounts, account_spec)
        unmanaged = unmanaged_accounts(log, deployed_accounts, account_spec)
        if unmanaged:
            log.warn("Unmanaged accounts in Org: %s" % (', '.join(unmanaged)))

    if args['alias']:
        queue_threads(log, deployed_accounts, set_account_alias,
                f_args=(log, args, account_spec), thread_count=10)

    if args['invite']:
        invite_account(log, args, org_client, deployed_accounts)
        

if __name__ == "__main__":
    main()
