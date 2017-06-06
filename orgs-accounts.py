#!/usr/bin/python

import boto3

org_client = boto3.client('organizations')




#
# Account functions
#

accounts = org_client.list_accounts()['Accounts']

def find_in_dictlist (dictlist, searchkey, searchvalue, returnkey):
    if not filter(lambda d: searchkey in d and returnkey in d, dictlist):
        return None
    values = map(lambda d: d[searchkey], dictlist)
    if len(values) != len(set(values)):
        return None
    result = filter(lambda d: d[searchkey] == searchvalue, dictlist)
    if len(result) == 1:
        return result[0][returnkey]
    else:
        return None

def find_in_accounts(seachkey, searchvalue, returnkey):
    if searchvalue in map(lambda d: d[searchkey], accounts):
        return filter(lambda d: d[searchkey] == searchvalue, accounts)[0][returnkey]
    else:
        return None

def build_account_lookup_table():
    account_lookup_table = {}
    for account in org_client.list_accounts()['Accounts']:
        account_lookup_table[account['Name']] = account['Id']
    return account_lookup_table

def account_exists(account_name, account_table):
    return account_name in account_table.keys()

def get_account_id_by_name(account_name, account_table):
    if account_name in account_table.keys():
        return account_table[account_name]
    else:
        return None

def get_parent_id(account_id):
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    if len(parents) == 1:
        return parents[0]['Id']
    else:
        #handle error
        print 'account', account_id, 'has more than one parent', parents
        return None

# returns a list of accounts attached to an OU
def get_accounts_in_ou (ou_id):
    account_list = org_client.list_accounts_for_parent(
        ParentId=ou_id,
    )['Accounts']
    return account_list

def account_in_ou(account_id, ou_id):
    if get_parent_id(account_id) == ou_id:
        return True
    else:
        return False

# returns sorted list of account names from a list of accounts
def get_account_names (account_list):
    names = []
    for account in account_list:
        names.append(account['Name'])
    return sorted(names)

def get name_by_id(account_id):

account_table = build_account_lookup_table()
print account_table
print account_table.keys()
print
account_name = 'Security'
print account_exists(account_name, account_table)
print
account_id = get_account_id_by_name(account_name, account_table)
print account_id
print
parent_id = get_parent_id(account_id)
print parent_id
print
print get_accounts_in_ou(parent_id)
print
print account_in_ou(account_id, parent_id)
print
print get_account_names(get_accounts_in_ou(parent_id))






# # add/remove accounts in this ou based on the ou spec
# def manage_account_attachments(spec_ou, existing_ou_id, account_table):
#     # attach specified accounts
#     account_spec = get_account_spec(spec_ou)
#     for account_name in account_spec:
#         account_id = get_account_id_by_name(account_name, account_table)
#         print account_table
#         print account_id
#         #if not account_in_ou(account_id, existing_ou_id) and not ensure_absent(spec_ou):
#         #    if not args.silent:
#         #        print "attaching account %s to OU %s" % (account_name, spec_ou['Name'])
#             #if not args.dryrun:
#             #    attach_account(account_id, existing_ou_id)
# 
