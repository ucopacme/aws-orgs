#!/usr/bin/python
#
# generate STS credentials 

"""Tools for basic AWS session setup.

Usage:
  assume_role.py (-h | --help)
  assume_role.py --version
  assume_role.py [--mfa-token <token>] [--profile <profile>]

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -p, --profile <profile>    AWS credentials profile to use [default: default].
  -m, --mfa-token <token>    6 digit tokencode provided by MFA device.

"""


import boto3
from docopt import docopt

args = docopt(__doc__)

# set env var for org config
# check for org config
# create org config

session = boto3.Session(profile_name=args['--profile'])
sts_client = session.client('sts')
credentials = sts_client.assume_role()['Credentials'] 

print "export AWS_ACCESS_KEY_ID=%s" % credentials['AccessKeyId']
print "export AWS_SECRET_ACCESS_KEY=%s" % credentials['SecretAccessKey']
print "export AWS_SECURITY_TOKEN=%s" % credentials['SessionToken']
print "export AWS_SECURITY_TOKEN_EXPIRATION='%s'" % credentials['Expiration']

