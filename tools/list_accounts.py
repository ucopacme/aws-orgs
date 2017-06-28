#!/usr/bin/python
#
# generate STS credentials 

"""Tools for basic AWS session setup.

Usage:
  list_accounts.py (-h | --help)
  list_accounts.py --version
  list_accounts.py [--mfa-token <token>] [--profile <profile>]

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -m, --mfa-token <token>    6 digit tokencode provided by MFA device.

"""


import boto3
from docopt import docopt

# create session
args = docopt(__doc__)
session = boto3.Session(profile_name=args['--profile'])

# get list of all account in this organization
org_client = session.client('organizations')
account_list = org_client.list_accounts()['Accounts']

# create local hash of account names and IDs.
account_hash = {}
for account in account_list:
     account_hash[account['Name']] = {
         'Id': account['Id']
     }
 
# make sorted array of account names
account_names = account_hash.keys()
account_names.sort()

# create profiles for the assumed role
role_name = 'OrganizationAccountAccessRole'


for profile in account_names:
    print
    print "[profile %s]" % profile
    print "role_arn = arn:aws:iam::%s:role/%s" % (account_hash[profile]['Id'], role_name)
    print "role_session_name = %s-%s" % (account_hash[profile]['Id'], role_name)
    print "source_profile = %s" % args['--profile']


"""
import ConfigParser

# New instance with 'bar' and 'baz' defaulting to 'Life' and 'hard' each
config = ConfigParser.SafeConfigParser({'bar': 'Life', 'baz': 'hard'})
config.read('example.cfg')

print config.get('Section1', 'foo')  # -> "Python is fun!"
config.remove_option('Section1', 'bar')
config.remove_option('Section1', 'baz')
print config.get('Section1', 'foo')  # -> "Life is hard!"


https://docs.python.org/2/library/configparser.html#examples
"""



