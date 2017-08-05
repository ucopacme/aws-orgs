#!/usr/bin/python


"""Manage recources in an AWS Organization.

Usage:
  awsorgs report [-d] [--boto-log]
  awsorgs organization (--spec-file FILE) [--exec] [-vd] [--boto-log]
  awsorgs --version
  awsorgs --help

Modes of operation:
  report         Display organization status report only.
  orgnanizaion   Run AWS Org management tasks per specification.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -s FILE, --spec-file FILE  AWS Org specification file in yaml format.
  --exec                     Execute proposed changes to AWS Org.
  -v, --verbose              Log to activity to STDOUT at log level INFO.
  -d, --debug                Increase log level to 'DEBUG'. Implies '--verbose'.
  --boto-log                 Include botocore and boto3 logs in log stream.

"""


import yaml
import json
import time

import boto3
from docopt import docopt

import awsorgs
from awsorgs import (
        lookup,
        get_logger,
        ensure_absent,
        get_root_id,
        validate_master_id)


def enable_policy_type_in_root(org_client, root_id):
    """
    Ensure policy type 'SERVICE_CONTROL_POLICY' is enabled in the
    organization root.
    """
    p_type = org_client.describe_organization(
            )['Organization']['AvailablePolicyTypes'][0]
    if (p_type['Type'] == 'SERVICE_CONTROL_POLICY'
            and p_type['Status'] != 'ENABLED'):
        org_client.enable_policy_type(
                RootId=root_id,
                PolicyType='SERVICE_CONTROL_POLICY')


def validate_spec_file(args):
    """
    Validate spec-file is properly formed.
    """
    org_spec = yaml.load(open(args['--spec-file']).read())
    spec_str = ['master_account_id', 'default_policy', 'default_ou' ]
    for s in spec_str:
        if not s in org_spec:
            msg = "Invalid spec-file: missing required param '%s'." % s
            raise RuntimeError(msg)
        if not isinstance(org_spec[s], str):
            msg = "Invalid spec-file: '%s' must be type 'str'." % s
            raise RuntimeError(msg)
    spec_list = ['organizational_unit_spec', 'policy_spec']
    for a in spec_list:
        if not a in org_spec:
            msg = "Invalid spec-file: missing required param '%s'." % a
            raise RuntimeError(msg)
        if not isinstance(org_spec[a], list):
            msg = "Invalid spec-file: '%s' must be type 'list'." % a
            raise RuntimeError(msg)

    # Validate this policy_spec is properly formed.
    err_prefix = "Malformed policy in spec-file:"
    for p_spec in org_spec['policy_spec']:
        if not isinstance(p_spec, dict):
            msg = "%s not a dictionary: '%s'" % (err_prefix, str(p_spec))
            raise RuntimeError(msg)
        if not 'Name' in p_spec:
            msg = "%s missing 'Name' key: '%s'" % (err_prefix, str(p_spec))
            raise RuntimeError(msg)
        # dont manage default policy
        if p_spec['Name'] == org_spec['default_policy']:
            org_spec['policy_spec'].remove(p_spec)
            break
        if not ensure_absent(p_spec):
            required_keys = ['Description', 'Effect', 'Actions']
            for key in required_keys:
                if not key in p_spec:
                    msg = ("%s '%s': missing required param '%s'" %
                            (err_prefix, p_spec['Name'], key))
                    raise RuntimeError(msg)
            if not isinstance(p_spec['Actions'], list):
                msg = ("%s '%s': 'Actions' must be type list." %
                        (err_prefix, p_spec['Name']))
                raise RuntimeError(msg)

    # recursive function to validate ou_spec are properly formed.
    def validate_ou_spec(ou_spec_list):
        global account_map, ou_list
        err_prefix = "Malformed OU in spec-file:"
        for ou_spec in ou_spec_list:
            if not isinstance(ou_spec, dict):
                msg = err_prefix + "not a dictionary: '%s'" % str(ou_spec)
                raise RuntimeError(msg)
            if not 'Name' in ou_spec:
                msg = err_prefix + "missing 'Name' key near: '%s'" % str(ou_spec)
                raise RuntimeError(msg)
            ou_list.append(ou_spec['Name'])
            # check for children OUs. recurse before running other tests
            if 'Child_OU' in ou_spec and isinstance(ou_spec['Child_OU'], list):
                validate_ou_spec(ou_spec['Child_OU'])
            # check for optional keys
            optional_keys = ['Accounts', 'Policies', 'Child_OU']
            for key in optional_keys:
                if key in ou_spec and ou_spec[key]:
                    if ensure_absent(ou_spec):
                        msg = ("%s OU '%s' is 'absent, but '%s' is populated." %
                                (err_prefix, ou_spec['Name'], key))
                        raise RuntimeError(msg)
                    if not isinstance(ou_spec[key], list):
                        msg = ("%s OU '%s': value of '%s' must be a list." %
                                (err_prefix, ou_spec['Name'], key))
                        raise RuntimeError(msg)

                # build mapping of accounts to ou_names
                # make sure accounts are unique across org
                if key == 'Accounts' and key in ou_spec and ou_spec['Accounts']:
                    for account in ou_spec['Accounts']:
                        if account in account_map:
                            msg = ("%s account %s set in multiple OU: %s, %s" %
                                    ( err_prefix, account,
                                    account_map[account], ou_spec['Name']))
                            raise  RuntimeError(msg)
                        else:
                            account_map[account] = ou_spec['Name']

    # initailize lists of managed resources
    global account_map, ou_list
    account_map = {}
    ou_list = []
    policy_list = map(lambda p: p['Name'], org_spec['policy_spec'])
    # pretent we manage default_policy
    policy_list.append(org_spec['default_policy'])

    # call recursive function to validate OUs.
    #   side effect: populate account_map, ou_list.
    validate_ou_spec(org_spec['organizational_unit_spec'])
    org_spec['managed'] = dict(
            accounts = account_map.keys(),
            ou       = ou_list,
            policies = policy_list)
    return org_spec


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


def scan_deployed_policies(org_client):
    return org_client.list_policies(
        Filter='SERVICE_CONTROL_POLICY'
    )['Policies']


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
        raise RuntimeError("API Error: account '%s' has more than one parent: "
                % (account_id, parents))


def manage_account_moves(org_client, args, log, deployed_accounts,
        ou_spec, dest_parent_id):
    """
    Alter deployed AWS Organization.  Ensure accounts are contained
    by designated OrganizationalUnits based on OU specification.
    """
    if 'Accounts' in ou_spec and ou_spec['Accounts']:
        for account in ou_spec['Accounts']:
            account_id = lookup(deployed_accounts, 'Name', account, 'Id')
            if not account_id:
                log.warn("Account '%s' not yet in Org" % account)
            else:
                source_parent_id = get_parent_id(org_client, account_id)
                if dest_parent_id != source_parent_id:
                    log.info("Moving account '%s' to OU '%s'" %
                            (account, ou_spec['Name']))
                    if args['--exec']:
                        org_client.move_account(
                                AccountId=account_id,
                                SourceParentId=source_parent_id,
                                DestinationParentId=dest_parent_id)


def place_unmanged_accounts(org_client, args, log, deployed, account_list,
        dest_parent):
    """
    Move any unmanaged accounts into the default OU.
    """
    for account in account_list:
        account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
        dest_parent_id   = lookup(deployed['ou'], 'Name', dest_parent, 'Id')
        source_parent_id = get_parent_id(org_client, account_id)
        if dest_parent_id and dest_parent_id != source_parent_id:
            log.info("Moving unmanged account '%s' to default OU '%s'" %
                    (account, dest_parent))
            if args['--exec']:
                org_client.move_account(
                        AccountId=account_id,
                        SourceParentId=source_parent_id,
                        DestinationParentId=dest_parent_id)


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
            TargetId=ou_id, Filter='SERVICE_CONTROL_POLICY',)['Policies']
    return sorted(map(lambda ou: ou['Name'], policies_in_ou))


def specify_policy_content(p_spec):
    """
    Compose and return (as json string) a policy content specification as
    per the given policy spec ('p_spec').
    """
    return """{ "Version": "2012-10-17", "Statement": [ { "Effect": "%s", "Action": %s, "Resource": "*" } ] }""" % (p_spec['Effect'], json.dumps(p_spec['Actions']))


def display_provisioned_policies(org_client, log, deployed_policies):
    """
    Print report of currently deployed Service Control Policies in
    AWS Organization.
    """
    header = "Provisioned Service Control Policies:"
    overbar = '_' * len(header)
    log.info("\n%s\n%s" % (overbar, header))
    for policy in deployed_policies:
        log.info("Name:\t\t%s\nDescription:\t%s\nId:\t\t%s" %
                (policy['Name'], policy['Description'], policy['Id']))
        log.info("Content:\t%s\n" %
                get_policy_content(org_client, policy['Id']))


def manage_policies(org_client, args, log, deployed_policies, policy_spec):
    """
    Manage Service Control Policies in the AWS Organization.  Make updates
    according to the policy specification ('policy_spec').  Do not touch
    the default policy.  Do not delete an attached policy.
    """
    for p_spec in policy_spec:
        policy_name = p_spec['Name']
        # dont touch default policy
        if not policy_name == args['default_policy']:
            policy_id = lookup(deployed_policies, 'Name', policy_name, 'Id')
            # policy already exists
            if policy_id:
                # check if we need to delete policy
                if ensure_absent(p_spec):
                    log.info("Deleting policy '%s'" % (policy_name))
                    # dont delete attached policy
                    if org_client.list_targets_for_policy(
                            PolicyId=policy_id)['Targets']:
                        log.error("Cannot delete policy '%s'. Still attached to OU" %
                                (policy_name))
                    elif args['--exec']:
                        org_client.delete_policy(PolicyId=policy_id)
                # check for policy updates
                elif (p_spec['Description'] !=
                        lookup(deployed_policies,'Id',policy_id,'Description')
                        or specify_policy_content(p_spec) !=
                        get_policy_content(org_client, policy_id)):
                    log.info("Updating policy '%s'" % (policy_name))
                    if args['--exec']:
                        org_client.update_policy(
                                PolicyId=policy_id,
                                Content=specify_policy_content(p_spec),
                                Description=p_spec['Description'],)
            # create new policy
            elif not ensure_absent(p_spec):
                log.info("Creating policy '%s'" % (policy_name))
                if args['--exec']:
                    org_client.create_policy(
                            Content=specify_policy_content(p_spec),
                            Description=p_spec['Description'],
                            Name=p_spec['Name'],
                            Type='SERVICE_CONTROL_POLICY')


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
    child_ou = org_client.list_organizational_units_for_parent(
            ParentId=parent_id)['OrganizationalUnits']
    accounts = org_client.list_accounts_for_parent(
            ParentId=parent_id)['Accounts']

    if not deployed_ou:
        deployed_ou.append(dict(
                Name = parent_name,
                Id = parent_id,
                Child_OU = [ou['Name'] for ou in child_ou if 'Name' in ou],
                Accounts = [acc['Name'] for acc in accounts if 'Name' in acc]))
    else:
        for ou in deployed_ou:
            if ou['Name'] == parent_name:
                ou['Child_OU'] = map(lambda d: d['Name'], child_ou)
                ou['Accounts'] = map(lambda d: d['Name'], accounts)
    for ou in child_ou:
        ou['ParentId'] = parent_id
        deployed_ou.append(ou)
        build_deployed_ou_table(org_client, ou['Name'], ou['Id'], deployed_ou)


def display_provisioned_ou(org_client, log, deployed_ou, parent_name,
        indent=0):
    """
    Recursive function to display the deployed AWS Organization structure.
    """
    # query aws for child orgs
    parent_id = lookup(deployed_ou, 'Name', parent_name, 'Id')
    child_ou_list = lookup(deployed_ou, 'Name', parent_name, 'Child_OU')
    child_accounts = lookup(deployed_ou, 'Name', parent_name, 'Accounts')
    # display parent ou name
    tab = '  '
    log.info(tab*indent + parent_name + ':')
    # look for policies
    policy_names = list_policies_in_ou(org_client, parent_id)
    if len(policy_names) > 0:
        log.info(tab*indent + tab + 'Policies: ' + ', '.join(policy_names))
    # look for accounts
    account_list = sorted(child_accounts)
    if len(account_list) > 0:
        log.info(tab*indent + tab + 'Accounts: ' + ', '.join(account_list))
    # look for child OUs
    if child_ou_list:
        log.info(tab*indent + tab + 'Child_OU:')
        indent+=2
        for ou_name in child_ou_list:
            # recurse
            display_provisioned_ou(org_client, log, deployed_ou, ou_name,indent)


def manage_policy_attachments(org_client, args, log, deployed_policies,
        ou_spec, ou_id):
    """
    Attach or detach specified Service Control Policy to a deployed 
    OrganizatinalUnit.  Do not detach the default policy ever.
    """
    # create lists policies_to_attach and policies_to_detach
    attached_policy_list = list_policies_in_ou(org_client, ou_id)
    if 'Policies' in ou_spec and isinstance(ou_spec['Policies'],list):
        spec_policy_list = ou_spec['Policies']
    else:
        spec_policy_list = []
    policies_to_attach = [p for p in spec_policy_list
            if p not in attached_policy_list]
    policies_to_detach = [p for p in attached_policy_list
            if p not in spec_policy_list
            and p != args['default_policy']]
    # attach policies
    for policy_name in policies_to_attach:
        if not lookup(deployed_policies,'Name',policy_name):
            raise RuntimeError("spec-file: ou_spec: policy '%s' not defined" %
                    policy_name)
        if not ensure_absent(ou_spec):
            log.info("Attaching policy '%s' to OU '%s'" %
                    (policy_name, ou_spec['Name']))
            if args['--exec']:
                org_client.attach_policy(
                        PolicyId=lookup(
                                deployed_policies, 'Name', policy_name, 'Id'),
                        TargetId=ou_id)
    # detach policies
    for policy_name in policies_to_detach:
        log.info("Detaching policy '%s' from OU '%s'" %
                (policy_name, ou_spec['Name']))
        if args['--exec']:
            org_client.detach_policy(PolicyId=lookup(deployed_policies,
                    'Name', policy_name, 'Id'), TargetId=ou_id)


def manage_ou (org_client, args, log, deployed, ou_spec_list, parent_name):
    """
    Recursive function to manage OrganizationalUnits in the AWS
    Organization.
    """
    for ou_spec in ou_spec_list:

        # ou exists
        ou = lookup(deployed['ou'], 'Name', ou_spec['Name'])
        if ou:

            # check for child_ou. recurse before other tasks.
            if 'Child_OU' in ou_spec:
                manage_ou(org_client, args, log, deployed,
                        ou_spec['Child_OU'], ou_spec['Name'])

            # check if ou 'absent'
            if ensure_absent(ou_spec):
                # error if ou contains anything
                for key in ['Accounts', 'Policies', 'Child_OU']:
                    if key in ou and ou[key]:
                        msg = ("Can not delete OU '%s'. deployed '%s' exists." %
                                (ou_spec['Name'], key))
                        raise RuntimeError(msg)

                # delete ou
                log.info("Deleting OU %s" % ou_spec['Name'])
                if args['--exec']:
                    org_client.delete_organizational_unit(
                            OrganizationalUnitId=ou['Id'])

            else:
                manage_policy_attachments( org_client, args, log,
                        deployed['policies'], ou_spec, ou['Id'])
                manage_account_moves( org_client, args, log,
                        deployed['accounts'], ou_spec, ou['Id'])

        elif not ensure_absent(ou_spec):
            # ou does not exist
            log.info("Creating new OU '%s' under parent '%s'" %
                    (ou_spec['Name'], parent_name))
            if args['--exec']:
                new_ou = org_client.create_organizational_unit(
                        ParentId=lookup(deployed['ou'],'Name',parent_name,'Id'),
                        Name=ou_spec['Name'])['OrganizationalUnit']
                manage_policy_attachments(org_client, args, log,
                        deployed['policies'], ou_spec, new_ou['Id'])
                manage_account_moves(org_client, args, log,
                        deployed['accounts'], ou_spec, new_ou['Id'])
                if ('Child_OU' in ou_spec and isinstance(new_ou, dict)
                        and 'Id' in new_ou):
                    # recurse
                    manage_ou( org_client, args, log, deployed,
                            ou_spec['Child_OU'], new_ou['Name'])


def main():
    args = docopt(__doc__, version='awsorgs 0.0.0')
    log = get_logger(args)
    org_client = boto3.client('organizations')
    root_id = get_root_id(org_client)
    deployed = dict(
            policies = scan_deployed_policies(org_client),
            accounts = scan_deployed_accounts(org_client),
            ou = scan_deployed_ou(org_client, root_id))

    if args['--spec-file']:
        org_spec = validate_spec_file(args)
        validate_master_id(org_client, org_spec)

    if args['report']:
        header = 'Provisioned Organizational Units in Org:'
        overbar = '_' * len(header)
        log.info("\n%s\n%s" % (overbar, header))
        display_provisioned_ou(org_client, log, deployed['ou'], 'root')
        display_provisioned_policies(org_client, log, deployed['policies'])

    if args['organization']:
        enable_policy_type_in_root(org_client, root_id)
        args['default_policy'] = org_spec['default_policy']

        manage_policies(org_client, args, log, deployed['policies'],
                org_spec['policy_spec'])
        # rescan deployed policies
        deployed['policies'] = scan_deployed_policies(org_client)
        manage_ou(org_client, args, log, deployed,
                org_spec['organizational_unit_spec'], 'root')

        # check for unmanaged resources
        for key in org_spec['managed'].keys():
            unmanaged= [a for a in map(lambda a: a['Name'], deployed[key])
                    if a not in org_spec['managed'][key] ]
            # warn about unmanaged org resources
            if unmanaged:
                log.warn("Unmanaged %s in Org: %s" %
                        (key,', '.join(unmanaged)))
                if key ==  'accounts':
                    # append unmanaged accounts to default_ou
                    place_unmanged_accounts(org_client, args, log, deployed,
                            unmanaged, org_spec['default_ou'])


if __name__ == "__main__":
    main()
