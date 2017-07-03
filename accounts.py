#!/usr/bin/python


"""Manage recources in an AWS Organization.

Usage:
  accounts.py report [--profile <profile>] [--verbose] [--log-target <target>]...
  accounts.py accounts (--spec-file FILE) [--exec]
                       [--profile <profile>] [--verbose] [--log-target <target>]...
  accounts.py (-h | --help)
  accounts.py --version

Modes of operation:
  report         Display organization status report only.
  accounts       Create new accounts in AWS Org per specifation.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -s FILE, --spec-file FILE  AWS account specification file in yaml format.
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
import yaml
import json
import time
from docopt import docopt
from awsorgs import lookup, logger




#
# General functions
#

def get_root_id(org_client):
    """
    Query deployed AWS Organization for its Root ID.
    """
    roots = org_client.list_roots()['Roots']
    if len(roots) >1:
        raise RuntimeError(
            "org_client.list_roots returned multiple roots.  Go figure!"
        )
    return roots[0]['Id']


def validate_spec_file(spec_file):
    """
    Validate spec-file is properly formed.
    """
    spec = yaml.load(open(args['--spec-file']).read())
    return spec
                    
#def lookup(dlist, lkey, lvalue, rkey=None):
#    """
#    Use a known key:value pair to lookup a dictionary in a list of
#    dictionaries.  Return the dictonary or None.  If rkey is provided,
#    return the value referenced by rkey or None.  If more than one
#    dict matches, raise an error.
#    args:
#        dlist:   lookup table -  a list of dictionaries
#        lkey:    name of key to use as lookup criteria
#        lvalue:  value to use as lookup criteria
#        key:     (optional) name of key referencing a value to return
#    """
#    items = [d for d in dlist
#             if lkey in d
#             and d[lkey] == lvalue]
#    if not items:
#        return None
#    if len(items) > 1:
#        raise RuntimeError(
#            "Data Error: lkey:lvalue lookup matches multiple items in dlist"
#        )
#    if rkey:
#        if rkey in items[0]:
#            return items[0][rkey]
#        return None
#    return items[0]
#
#
#def logger(log, message):
#    if message:
#        log.append(message)
#    return



#
# Account functions
#


def scan_deployed_accounts(org_client):
    """
    Query AWS Organization for deployed accounts.
    Returns a list of dictionary.
    """
    accounts = org_client.list_accounts()
    deployed_accounts = accounts['Accounts']
    while 'NextToken' in accounts and accounts['NextToken']:
        accounts = org_client.list_accounts()
        deployed_accounts += accounts['Accounts']
    # only return accounts that have an 'Name' key
    return [d for d in deployed_accounts if 'Name' in d ]


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
    Compare deployed_ accounts to list of accounts in account_spec.
    Create accounts not found in deployed_accounts.
    """
    for a_spec in account_spec:
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
        logger(log, "Name:\t\t%s\nEmail:\t\t%s\nId:\t\t%s\n" %
                (a_name, a_email, a_id))



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
        spec = validate_spec_file(args['--spec-file'])
        # dont mangle the wrong org by accident
        master_account_id = org_client.describe_organization(
                )['Organization']['MasterAccountId']
        if master_account_id != spec['master_account_id']:
            errmsg = ("""The Organization Master Account Id '%s' does not
              match the 'master_account_id' set in the spec-file.  
              Is your '--profile' arg correct?""" % master_account_id)
            raise RuntimeError(errmsg)


    if args['report']:
        display_provisioned_accounts(log, deployed_accounts)


    if args['accounts']:
        deployed_accounts = scan_deployed_accounts(org_client)
        logger(log, "Running AWS account creation.")
        if not args['--exec']:
            logger(log, "This is a dry run!\n")
        create_accounts(org_client, args, log, deployed_accounts,
                spec['accounts'])

        # check for unmanaged accounts
        unmanaged= [ a for a in map(lambda a: a['Name'], deployed_accounts)
                    if a not in map(lambda a: a['Name'], spec['accounts']) ]
        # warn about unmanaged org resources
        if unmanaged:
            logger(
                log, "Warning: unmanaged accounts in Org: %s" %
                (', '.join(unmanaged))
            )


    if args['--verbose']:
        for line in log:
            print line

