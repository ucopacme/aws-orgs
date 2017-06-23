#!/usr/bin/python


"""Manage recources in an AWS Organization.

Usage:
  awsorgs.py report [--profile <profile>] [--verbose] [--log-target <target>]...
  awsorgs.py (organization | accounts) (--spec-file FILE) [--exec]
                [--profile <profile>] [--verbose] [--log-target <target>]...
  awsorgs.py (-h | --help)
  awsorgs.py --version

Modes of operation:
  report         Display organization status report only.
  orgnanizaion   Run AWS Org management tasks per specification.
  accounts       Create new accounts in AWS Org per specifation.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -s FILE, --spec-file FILE  AWS Org specification file in yaml format.
  --exec                     Execute proposed changes to AWS Org.
  -l, --log-target <target>  Where to send log output.  This option can be
                             repeated to specicy multiple targets.
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


def enable_policy_type_in_root(org_client, root_id):
    """
    ensure policy type 'SERVICE_CONTROL_POLICY' is enabled in the
    organization root.
    """
    p_type = org_client.describe_organization()['Organization']['AvailablePolicyTypes'][0]
    if p_type['Type'] == 'SERVICE_CONTROL_POLICY' and p_type['Status'] != 'ENABLED':
        org_client.enable_policy_type(
            RootId=root_id,
            PolicyType='SERVICE_CONTROL_POLICY'
        )


def ensure_absent(spec):
    """
    test if an 'Ensure' key is set to absent in dictionary 'spec'
    """
    if 'Ensure' in spec and spec['Ensure'] == 'absent':
        return True
    else:
        return False


def lookup(dlist, lkey, lvalue, rkey=None):
    """
    Use a known key:value pair to lookup a dictionary in a list of
    dictionaries.  Return the dictonary or None.  If rkey is provided,
    return the value referenced by rkey or None.  If more than one
    dict matches, raise an error.
    args:
        dlist:   lookup table -  a list of dictionaries
        lkey:    name of key to use as lookup criteria
        lvalue:  value to use as lookup criteria
        key:     (optional) name of key referencing a value to return
    """
    items = [d for d in dlist
             if lkey in d
             and d[lkey] == lvalue]
    if not items:
        return None
    if len(items) > 1:
        raise RuntimeError(
            "Data Error: lkey:lvalue lookup matches multiple items in dlist"
        )
    if rkey:
        if rkey in items[0]:
            return items[0][rkey]
        return None
    return items[0]


def logger(log, message):
    if message:
        log.append(message)
    return



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


def get_parent_id(org_client, account_id):
    """
    Query deployed AWS organanization for 'account_id. Return the 'Id' of
    the parent OrganizationalUnit or 'None'.
    """
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    try:
        len(parents) == 1
        return parents[0]['Id']
    except:
        raise RuntimeError("API Error: account %s has more than one parent: "
                % (account_id, parents))


def list_accounts_in_ou(org_client, ou_id):
    """
    Query deployed AWS organanization for accounts contained in
    OrganizationalUnit ('ou_id').  Return a list of account names.
    """
    account_list = org_client.list_accounts_for_parent(
        ParentId=ou_id
    )['Accounts']
    return sorted([d['Name'] for d in account_list if 'Name' in d])


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
                logger(log, "Account %s created, but not yet fully provisioned"
                        % a_spec['Name'])
                return lookup(created_accounts, 'AccountName', a_spec['Name'],
                        'AccountId')

            # create a new account
            logger(log, "creating account: %s" % (a_spec['Name']))
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



def display_provissioned_accounts(log, deployed_accounts):
    """
    Print report of currently deployed accounts in AWS Organization.
    """
    header = "Provissioned Accounts in Org:"
    overbar = '_' * len(header)
    logger(log, "\n%s\n%s" % (overbar, header))
    for a_name in sorted(map(lambda a: a['Name'], deployed_accounts)):
        a_id = lookup(deployed_accounts, 'Name', a_name, 'Id')
        a_email = lookup(deployed_accounts, 'Name', a_name, 'Email')
        logger(log, "Name:\t\t%s\nEmail:\t\t%s\nId:\t\t%s\n" %
                (a_name, a_email, a_id))


def manage_accounts(org_client, args, log, deployed_accounts, deployed_ou,
        account_spec):
    """
    Alter deployed AWS Organization.  Ensure accounts are contained
    by designated OrganizationalUnits based on account specification
    ('account_spec').
    """
    for a_spec in account_spec:
        account_id = lookup(deployed_accounts, 'Name', a_spec['Name'], 'Id')
        if not account_id:
            logger(log,"Warning: account %s not in Org." % (a_spec['Name']))
        else:
            # locate account in correct ou
            parent_id = get_parent_id(org_client, account_id)
            parent_ou_name = lookup(deployed_ou, 'Id', parent_id, 'Name')
            if not 'OU' in a_spec or not a_spec['OU']:
                a_spec['OU'] = 'root'
            if a_spec['OU'] != parent_ou_name:
                logger(log, "moving account %s from ou %s to ou %s" %
                        (a_spec['Name'], parent_ou_name, a_spec['OU'] ))
                if args['--exec']:
                    ou_id = lookup(deployed_ou, 'Name', a_spec['OU'], 'Id')
                    org_client.move_account(AccountId=account_id,
                            SourceParentId=parent_id,
                            DestinationParentId=lookup(deployed_ou, 'Name',
                            a_spec['OU'], 'Id'))



#
# Policy functions
#

def get_policy_content(org_client, policy_id):
    """
    Query deployed AWS Organization. Return the policy content (json string)
    accociated with the Service Control Policy referenced by 'policy_id'.
    """
    return org_client.describe_policy(PolicyId=policy_id)['Policy']['Content']


def list_policies_in_ou (org_client, ou_id):
    """
    Query deployed AWS organanization.  Return a list (of type dict)
    of policies attached to OrganizationalUnit referenced by 'ou_id'.
    """
    policies_in_ou = org_client.list_policies_for_target(
        TargetId=ou_id,
        Filter='SERVICE_CONTROL_POLICY',
    )['Policies']
    return sorted(map(lambda ou: ou['Name'], policies_in_ou))


def specify_policy_content(p_spec):
    """
    Compose and return (as json string) a policy content specification as
    per the given policy spec ('p_spec').
    """
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (p_spec['Effect'], json.dumps(p_spec['Actions']))


def display_provissioned_policies(org_client, deployed_policies):
    """
    Print report of currently deployed Service Control Policies in
    AWS Organization.
    """
    header = "Provissioned Service Control Policies:"
    overbar = '_' * len(header)
    logger(log, "\n%s\n%s" % (overbar, header))
    for policy in deployed_policies:
        logger(log, "Name:\t\t%s\nDescription:\t%s\nId:\t\t%s" %
                (policy['Name'], policy['Description'], policy['Id']))
        logger(log, "Content:\t%s\n" %
                get_policy_content(org_client, policy['Id']))


def manage_policies(org_client, args, log, deployed_policies, policy_spec):
    """
    Manage Service Control Policies in the AWS Organization.  Make updates
    according to the policy specification ('policy_spec').
    """
    for p_spec in policy_spec:
        policy_name = p_spec['Name']
        policy_id = lookup(deployed_policies, 'Name', policy_name, 'Id')

        if policy_id and ensure_absent(p_spec):
            logger(log, "deleting policy: %s" % (policy_name))
            if args['--exec']:
                org_client.delete_policy(PolicyId=policy_id)

        else:
            if not policy_id:
                logger(log, "creating policy: %s" % (policy_name))
                if args['--exec']:
                    org_client.create_policy (
                        Content=specify_policy_content(p_spec),
                        Description=p_spec['Description'],
                        Name=p_spec['Name'],
                        Type='SERVICE_CONTROL_POLICY'
                    )

            else:
                if (p_spec['Description'] !=
                      lookup(deployed_policies,'Id',policy_id,'Description') or
                      specify_policy_content(p_spec) !=
                      get_policy_content(org_client, policy_id)):
                    logger(log, "updating policy: %s" % (policy_name))
                    if args['--exec']:
                        org_client.update_policy(
                            PolicyId=policy_id,
                            Content=specify_policy_content(p_spec),
                            Description=p_spec['Description'],
                        )




#
# OrganizaionalUnit functions
#

def scan_deployed_ou(org_client, root_id):
    """
    Query AWS Organization for OrganizationalUnits.
    Returns a list of dictionary.
    """
    deployed_ou = []
    build_deployed_ou_table(org_client, 'root', root_id, deployed_ou)
    return deployed_ou


def build_deployed_ou_table(org_client, parent_name, parent_id, deployed_ou):
    """
    Recursively traverse deployed AWS Organization.  Build the 'deployed_ou'
    lookup table (list of dictionaries).
    """
    children_ou = org_client.list_organizational_units_for_parent(
        ParentId=parent_id
    )['OrganizationalUnits']
    if not deployed_ou:
        deployed_ou.append(dict(
            Name = parent_name,
            Id = parent_id,
            Children = map(lambda d: d['Name'], children_ou),
        ))
    else:
        for ou in deployed_ou:
            if ou['Name'] == parent_name:
                ou['Children'] = map(lambda d: d['Name'], children_ou)
    for ou in children_ou:
        ou['ParentId'] = parent_id
        deployed_ou.append(ou)
        build_deployed_ou_table(org_client, ou['Name'], ou['Id'], deployed_ou)


def children_in_ou_spec(ou_spec):
    """
    Check if if 'ou_spec' has any child OU.  Returns boolean.
    """
    if 'OU' in ou_spec and isinstance(ou_spec['OU'], list):
        return True
    return False


def display_provissioned_ou(org_client, log, deployed_ou, parent_name,
        indent=0):
    """
    Recursive function to display the deployed AWS Organization structure.
    """
    # query aws for child orgs
    parent_id = lookup(deployed_ou, 'Name', parent_name, 'Id')
    child_ou_list = lookup(deployed_ou, 'Name', parent_name, 'Children')
    # display parent ou name
    tab = '  '
    logger(log, tab*indent + parent_name + ':')
    # look for policies
    policy_names = list_policies_in_ou(org_client, parent_id)
    if len(policy_names) > 0:
        logger(log, tab*indent + tab + 'policies: ' + ', '.join(policy_names))
    # look for accounts
    account_list = list_accounts_in_ou(org_client, parent_id)
    if len(account_list) > 0:
        logger(log, tab*indent + tab + 'accounts: ' + ', '.join(account_list))
    # look for child OUs
    if child_ou_list:
        logger(log, tab*indent + tab + 'child_ou:')
        indent+=2
        for ou_name in child_ou_list:
            # recurse
            display_provissioned_ou(org_client, log, deployed_ou, ou_name, indent)


def manage_policy_attachments(org_client, args, log, deployed_policies,
        ou_spec, ou_id):
    """
    Attach or detach specified Service Control Policy to a deployed 
    OrganizatinalUnit.  Do not detach the default policy ever.
    """
    # create lists policies_to_attach and policies_to_detach
    attached_policy_list = list_policies_in_ou(org_client, ou_id)
    if 'Policy' in ou_spec and isinstance(ou_spec['Policy'],list):
        spec_policy_list = ou_spec['Policy']
    else:
        spec_policy_list = []
    policies_to_attach = [p for p in spec_policy_list
            if p not in attached_policy_list]
    policies_to_detach = [p for p in attached_policy_list
            if p not in spec_policy_list
            and p != args['default_policy']]
    # attach policies
    for policy_name in policies_to_attach:
        if not ensure_absent(ou_spec):
            logger(log, "attaching policy %s to OU %s" %
                    (policy_name, ou_spec['Name']))
            if args['--exec']:
                org_client.attach_policy(PolicyId=lookup(deployed_policies,
                        'Name', policy_name, 'Id'), TargetId=ou_id)
    # detach policies
    for policy_name in policies_to_detach:
        logger(log, "detaching policy %s from OU %s" %
                (policy_name, ou_spec['Name']))
        if args['--exec']:
            org_client.detach_policy(PolicyId=lookup(deployed_policies,
                    'Name', policy_name, 'Id'), TargetId=ou_id)


def manage_ou (org_client, args, log, deployed_ou, deployed_policies,
        ou_spec_list, parent_name):
    """
    Recursive function to manage OrganizationalUnits in the AWS
    Organization.
    """
    for ou_spec in ou_spec_list:
        if lookup(deployed_ou, 'Name', ou_spec['Name']):
            # ou exists
            if children_in_ou_spec(ou_spec):
                # recurse
                manage_ou(org_client, args, log, deployed_ou,
                        deployed_policies, ou_spec['OU'], ou_spec['Name'])
            if ensure_absent(ou_spec):
                # delete ou
                logger(log,'deleting OU', ou_spec['Name'])
                if args['--exec']:
                    org_client.delete_organizational_unit(
                            OrganizationalUnitId=lookup(deployed_ou,
                            'Name', ou_spec['Name'], 'Id'))
            else:
                manage_policy_attachments(org_client, args, log,
                         deployed_policies, ou_spec,
                         lookup(deployed_ou,'Name',ou_spec['Name'],'Id'))

        elif not ensure_absent(ou_spec):
            # ou does not exist
            logger(log, "creating new ou %s under parent %s" %
                    (ou_spec['Name'], parent_name))
            if args['--exec']:
                new_ou = org_client.create_organizational_unit(
                    ParentId=lookup(deployed_ou, 'Name', parent_name, 'Id'),
                    Name=ou_spec['Name'])['OrganizationalUnit']
                manage_policy_attachments( org_client, args, log,
                        deployed_policies, ou_spec, new_ou['Id'])
                if (children_in_ou_spec(ou_spec) and 
                        isinstance(new_ou, dict) and 'Id' in new_ou):
                    # recurse
                    manage_ou(org_client, args, log, deployed_ou,
                            deployed_policies, ou_spec['OU'], new_ou['Name'])



#
# Main
#
if __name__ == "__main__":
    args = docopt(__doc__, version='awsorgs 0.0.0')

    session = boto3.Session(profile_name=args['--profile'])
    org_client = session.client('organizations')
    root_id = get_root_id(org_client)
    log = []


    if args['report']:
        deployed_policies = org_client.list_policies(
            Filter='SERVICE_CONTROL_POLICY')['Policies']
        deployed_accounts = scan_deployed_accounts(org_client)
        deployed_ou = scan_deployed_ou(org_client, root_id)

        header = 'Provisioned Organizational Units in Org:'
        overbar = '_' * len(header)
        logger(log, "\n%s\n%s" % (overbar, header))
        display_provissioned_ou(org_client, log, deployed_ou, 'root')
        display_provissioned_policies(org_client, deployed_policies)
        display_provissioned_accounts(log, deployed_accounts)


    if args['organization']:
        enable_policy_type_in_root(org_client, root_id)
        org_spec = yaml.load(open(args['--spec-file']).read())
        master_account_id = org_client.describe_organization(
                )['Organization']['MasterAccountId']
        if master_account_id != org_spec['master_account_id']:
            raise RuntimeError("The Organization Master Account Id '%s' does not match the 'master_account_id' set in the spec-file.  Is your '--profile' arg correct?" % master_account_id)

        args['default_policy'] = org_spec['default_policy']
        deployed_policies = org_client.list_policies(
            Filter='SERVICE_CONTROL_POLICY'
        )['Policies']
        deployed_accounts = scan_deployed_accounts(org_client)
        deployed_ou = scan_deployed_ou(org_client, root_id)

        logger(log, "Running AWS organization management.")
        if not args['--exec']: logger(log, "This is a dry run!\n")

        manage_policies(org_client, args, log, deployed_policies,
                org_spec['policy_spec'])
        manage_ou(org_client, args, log, deployed_ou, deployed_policies,
                org_spec['organizational_unit_spec'], 'root')
        manage_accounts(org_client, args, log, deployed_accounts,
                deployed_ou, org_spec['account_spec'])


    if args['accounts']:
        org_spec = yaml.load(open(args['--spec-file']).read())
        deployed_accounts = scan_deployed_accounts(org_client)
        logger(log, "Running AWS account creation.")
        if not args['--exec']:
            logger(log, "This is a dry run!\n")
        create_accounts(org_client, args, log, deployed_accounts,
                org_spec['account_spec'])


    if args['--verbose']:
        for line in log:
            print line
