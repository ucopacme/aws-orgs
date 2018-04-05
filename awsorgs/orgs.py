#!/usr/bin/env python


"""Manage recources in an AWS Organization.

Usage:
  awsorgs (report|organization) [--config FILE]
                                [--spec-dir PATH] 
                                [--master-account-id ID]
                                [--auth-account-id ID]
                                [--org-access-role ROLE]
                                [--exec] [-q] [-d|-dd]
  awsorgs (--help|--version)

Modes of operation:
  report         Display organization status report only.
  orgnanizaion   Run AWS Org management tasks per specification.

Options:
  -h, --help                Show this help message and exit.
  -V, --version             Display version info and exit.
  --config FILE             AWS Org config file in yaml format.
  --spec-dir PATH           Location of AWS Org specification file directory.
  --master-account-id ID    AWS account Id of the Org master account.    
  --auth-account-id ID      AWS account Id of the authentication account.
  --org-access-role ROLE    IAM role for traversing accounts in the Org.
  --exec                    Execute proposed changes to AWS Org.
  -q, --quiet               Repress log output.
  -d, --debug               Increase log level to 'DEBUG'.
  -dd                       Include botocore and boto3 logs in log stream.

"""


import yaml
import json
import time

import boto3
from docopt import docopt

import awsorgs
import awsorgs.utils
from awsorgs.utils import *
from awsorgs.spec import *


def validate_accounts_unique_in_org(log, root_spec):
    """
    Make sure accounts are unique across org
    """
    # recursively build mapping of accounts to ou_names
    def map_accounts(spec, account_map={}):
        if 'Accounts' in spec and spec['Accounts']:
            for account in spec['Accounts']:
                if account in account_map:
                    account_map[account].append(spec['Name'])
                else:
                    account_map[account] = [(spec['Name'])]
        if 'Child_OU' in spec and spec['Child_OU']:
            for child_spec in spec['Child_OU']:
                map_accounts(child_spec, account_map)
        return account_map
    # find accounts set to more than one OU
    unique = True
    for account, ou in list(map_accounts(root_spec).items()):
        if len(ou) > 1:
            log.error("Account '%s' set in multiple OU: %s" % (account, ou))
            unique = False
    if not unique:
        log.critical("Invalid org_spec: Do not assign accounts to multiple "
                "Organizatinal Units")
        sys.exit(1)


def enable_policy_type_in_root(org_client, root_id):
    """
    Ensure policy type 'SERVICE_CONTROL_POLICY' is enabled in the
    organization root.
    """
    p_type = org_client.list_roots()['Roots'][0]['PolicyTypes']
    if (not p_type or (p_type[0]['Type'] == 'SERVICE_CONTROL_POLICY'
            and p_type[0]['Status'] != 'ENABLED')):
        org_client.enable_policy_type(RootId=root_id, PolicyType='SERVICE_CONTROL_POLICY')


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


def list_policies_in_ou (org_client, ou_id):
    """
    Query deployed AWS organanization.  Return a list (of type dict)
    of policies attached to OrganizationalUnit referenced by 'ou_id'.
    """
    policies_in_ou = org_client.list_policies_for_target(
            TargetId=ou_id, Filter='SERVICE_CONTROL_POLICY',)['Policies']
    return sorted([ou['Name'] for ou in policies_in_ou])


def scan_deployed_policies(org_client):
    """
    Return list of Service Control Policies deployed in Organization
    """
    return org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']


def scan_deployed_ou(log, org_client, root_id):
    """
    Recursively traverse deployed AWS Organization.  Return list of
    organizational unit dictionaries.  
    """
    def build_deployed_ou_table(org_client, parent_name, parent_id, deployed_ou):
        # recusive sub function to build the 'deployed_ou' table
        response = org_client.list_organizational_units_for_parent( ParentId=parent_id)
        child_ou = response['OrganizationalUnits']
        while 'NextToken' in response and response['NextToken']:
            response = org_client.list_organizational_units_for_parent(
                ParentId=parent_id, NextToken=response['NextToken'])
            child_ou += response['OrganizationalUnits']

        response = org_client.list_accounts_for_parent( ParentId=parent_id)
        accounts = response['Accounts']
        while 'NextToken' in response and response['NextToken']:
            response = org_client.list_accounts_for_parent(
                ParentId=parent_id, NextToken=response['NextToken'])
            accounts += response['Accounts']
        log.debug('parent_name: %s; ou: %s' % (parent_name, yamlfmt(child_ou)))
        log.debug('parent_name: %s; accounts: %s' % (parent_name, yamlfmt(accounts)))

        if not deployed_ou:
            deployed_ou.append(dict(
                    Name = parent_name,
                    Id = parent_id,
                    Child_OU = [ou['Name'] for ou in child_ou if 'Name' in ou],
                    Accounts = [acc['Name'] for acc in accounts if 'Name' in acc]))
        else:
            for ou in deployed_ou:
                if ou['Name'] == parent_name:
                    ou['Child_OU'] = [d['Name'] for d in child_ou]
                    ou['Accounts'] = [d['Name'] for d in accounts]
        for ou in child_ou:
            ou['ParentId'] = parent_id
            deployed_ou.append(ou)
            build_deployed_ou_table(org_client, ou['Name'], ou['Id'], deployed_ou)

    # build the table 
    deployed_ou = []
    build_deployed_ou_table(org_client, 'root', root_id, deployed_ou)
    log.debug(yamlfmt(deployed_ou))
    return deployed_ou


def display_provisioned_policies(org_client, log, deployed):
    """
    Print report of currently deployed Service Control Policies in
    AWS Organization.
    """
    header = "Provisioned Service Control Policies:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for policy in deployed['policies']:
        log.info("\nName:\t\t%s" % policy['Name'])
        log.info("Description:\t%s" % policy['Description'])
        log.info("Id:\t%s" % policy['Id'])
        log.info("Content:")
        log.info(json.dumps(json.loads(org_client.describe_policy(
                PolicyId=policy['Id'])['Policy']['Content']),
                indent=2,
                separators=(',', ': ')))


def display_provisioned_ou(org_client, log, deployed_ou, parent_name, indent=0):
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
            display_provisioned_ou(org_client, log, deployed_ou, ou_name, indent)


def manage_account_moves(org_client, args, log, deployed, ou_spec, dest_parent_id):
    """
    Alter deployed AWS Organization.  Ensure accounts are contained
    by designated OrganizationalUnits based on OU specification.
    """
    if 'Accounts' in ou_spec and ou_spec['Accounts']:
        for account in ou_spec['Accounts']:
            account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
            if not account_id:
                log.warn("Account '%s' not yet in Organization" % account)
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


def place_unmanged_accounts(org_client, args, log, deployed, account_list, dest_parent):
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


def manage_policies(org_client, args, log, deployed, org_spec):
    """
    Manage Service Control Policies in the AWS Organization.  Make updates
    according to the sc_policies specification.  Do not touch
    the default policy.  Do not delete an attached policy.
    """
    for p_spec in org_spec['sc_policies']:
        policy_name = p_spec['Name']
        log.debug("considering sc_policy: %s" % policy_name)
        # dont touch default policy
        if policy_name == org_spec['default_sc_policy']:
            continue
        policy = lookup(deployed['policies'], 'Name', policy_name)
        # delete existing sc_policy
        if ensure_absent(p_spec):
            if policy:
                log.info("Deleting policy '%s'" % (policy_name))
                # dont delete attached policy
                if org_client.list_targets_for_policy( PolicyId=policy_id)['Targets']:
                    log.error("Cannot delete policy '%s'. Still attached to OU" %
                            policy_name)
                elif args['--exec']:
                    org_client.delete_policy(PolicyId=policy['Id'])
            continue
        # create or update sc_policy
        statement = dict(Effect=p_spec['Effect'], Action=p_spec['Actions'], Resource='*')
        policy_doc = json.dumps(dict(Version='2012-10-17', Statement=[statement]))
        log.debug("spec sc_policy_doc: %s" % yamlfmt(policy_doc))
        # create new policy
        if not policy:
            log.info("Creating policy '%s'" % policy_name)
            if args['--exec']:
                org_client.create_policy(
                        Content=policy_doc,
                        Description=p_spec['Description'],
                        Name=p_spec['Name'],
                        Type='SERVICE_CONTROL_POLICY')
        # check for policy updates
        else:
            deployed_policy_doc = json.dumps(json.loads(org_client.describe_policy(
                    PolicyId=policy['Id'])['Policy']['Content']))
            log.debug("real sc_policy_doc: %s" % yamlfmt(deployed_policy_doc))
            if (p_spec['Description'] != policy['Description']
                or policy_doc != deployed_policy_doc):
                log.info("Updating policy '%s'" % policy_name)
                if args['--exec']:
                    org_client.update_policy(
                            PolicyId=policy['Id'],
                            Content=policy_doc,
                            Description=p_spec['Description'],)


def manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou_id):
    """
    Attach or detach specified Service Control Policy to a deployed 
    OrganizatinalUnit.  Do not detach the default policy ever.
    """
    # create lists policies_to_attach and policies_to_detach
    attached_policy_list = list_policies_in_ou(org_client, ou_id)
    if 'SC_Policies' in ou_spec and isinstance(ou_spec['SC_Policies'], list):
        spec_policy_list = ou_spec['SC_Policies']
    else:
        spec_policy_list = []
    policies_to_attach = [p for p in spec_policy_list
            if p not in attached_policy_list]
    policies_to_detach = [p for p in attached_policy_list
            if p not in spec_policy_list
            and p != org_spec['default_sc_policy']]
    # attach policies
    for policy_name in policies_to_attach:
        if not lookup(deployed['policies'],'Name',policy_name):
            if args['--exec']:
                raise RuntimeError("spec-file: ou_spec: policy '%s' not defined" %
                        policy_name)
        if not ensure_absent(ou_spec):
            log.info("Attaching policy '%s' to OU '%s'" % (policy_name, ou_spec['Name']))
            if args['--exec']:
                org_client.attach_policy(
                        PolicyId=lookup(deployed['policies'], 'Name', policy_name, 'Id'),
                        TargetId=ou_id)
    # detach policies
    for policy_name in policies_to_detach:
        log.info("Detaching policy '%s' from OU '%s'" % (policy_name, ou_spec['Name']))
        if args['--exec']:
            org_client.detach_policy(
                    PolicyId=lookup(deployed['policies'], 'Name', policy_name, 'Id'),
                    TargetId=ou_id)


def manage_ou(org_client, args, log, deployed, org_spec, ou_spec_list, parent_name):
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
                manage_ou(org_client, args, log, deployed, org_spec,
                        ou_spec['Child_OU'], ou_spec['Name'])
            # check if ou 'absent'
            if ensure_absent(ou_spec):
                log.info("Deleting OU %s" % ou_spec['Name'])
                # error if ou contains anything
                error_flag = False
                for key in ['Accounts', 'SC_Policies', 'Child_OU']:
                    if key in ou and ou[key]:
                        log.error("Can not delete OU '%s'. deployed '%s' exists." %
                                (ou_spec['Name'], key))
                        error_flag = True
                if error_flag:
                    continue
                elif args['--exec']:
                    org_client.delete_organizational_unit(
                            OrganizationalUnitId=ou['Id'])
            # manage account and sc_policy placement in OU
            else:
                manage_policy_attachments(org_client, args, log,
                        deployed, org_spec, ou_spec, ou['Id'])
                manage_account_moves(org_client, args, log, deployed, ou_spec, ou['Id'])
        # create new OU
        elif not ensure_absent(ou_spec):
            log.info("Creating new OU '%s' under parent '%s'" %
                    (ou_spec['Name'], parent_name))
            if args['--exec']:
                new_ou = org_client.create_organizational_unit(
                        ParentId=lookup(deployed['ou'],'Name',parent_name,'Id'),
                        Name=ou_spec['Name'])['OrganizationalUnit']
                # account and sc_policy placement
                manage_policy_attachments(org_client, args, log,
                        deployed, org_spec, ou_spec, new_ou['Id'])
                manage_account_moves(org_client, args, log, deployed, ou_spec, new_ou['Id'])
                # recurse if child OU
                if ('Child_OU' in ou_spec and isinstance(new_ou, dict)
                        and 'Id' in new_ou):
                    manage_ou(org_client, args, log, deployed, org_spec,
                            ou_spec['Child_OU'], new_ou['Name'])


def main():
    args = docopt(__doc__, version=awsorgs.__version__)
    log = get_logger(args)
    log.debug(args)
    args = load_config(log, args)
    credentials = get_assume_role_credentials(
            args['--master-account-id'],
            args['--org-access-role'])
    if isinstance(credentials, RuntimeError):
        log.critical(credentials)
        sys.exit(1)
    org_client = boto3.client('organizations', **credentials)
    root_id = get_root_id(org_client)
    deployed = dict(
            policies = scan_deployed_policies(org_client),
            accounts = scan_deployed_accounts(log, org_client),
            ou = scan_deployed_ou(log, org_client, root_id))

    if args['report']:
        header = 'Provisioned Organizational Units in Org:'
        overbar = '_' * len(header)
        log.info("\n%s\n%s" % (overbar, header))
        display_provisioned_ou(org_client, log, deployed['ou'], 'root')
        display_provisioned_policies(org_client, log, deployed)

    if args['organization']:
        org_spec = validate_spec(log, args)
        root_spec = lookup(org_spec['organizational_units'], 'Name', 'root')
        validate_master_id(org_client, org_spec)
        validate_accounts_unique_in_org(log, root_spec)
        managed = dict(
                accounts = search_spec(root_spec, 'Accounts', 'Child_OU'),
                ou = search_spec(root_spec, 'Name', 'Child_OU'),
                policies = [p['Name'] for p in org_spec['sc_policies']])

        # ensure default_sc_policy is considered 'managed'
        if org_spec['default_sc_policy'] not in managed['policies']:
            managed['policies'].append(org_spec['default_sc_policy'])
        enable_policy_type_in_root(org_client, root_id)
        manage_policies(org_client, args, log, deployed, org_spec)

        # rescan deployed policies
        deployed['policies'] = scan_deployed_policies(org_client)
        manage_ou(org_client, args, log, deployed, org_spec,
                org_spec['organizational_units'], 'root')

        # check for unmanaged resources
        for key in list(managed.keys()):
            unmanaged= [a['Name'] for a in deployed[key] if a['Name'] not in managed[key]]
            if unmanaged:
                log.warn("Unmanaged %s in Organization: %s" % (key,', '.join(unmanaged)))
                if key ==  'accounts':
                    # append unmanaged accounts to default_ou
                    place_unmanged_accounts(org_client, args, log, deployed,
                            unmanaged, org_spec['default_ou'])


if __name__ == "__main__":
    main()
