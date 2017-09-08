#!/usr/bin/env python
"""Generatate AWS IAM user login profile and notify user with useful
instructions how to get started.

Usage:
  awsloginprofile USER [--new | --reset | --disable | --reenable] 
                  [--password PASSWORD] [--email EMAIL] [-vd] [--boto-log]
  awsloginprofile --help

Options:
  USER                  Name of IAM user.
  --new                 Create new login profile.
  --reset               Reset password for existing login profile.
  --disable             Delete existing login profile, disable access keys.
  --reenable            Recreate login profile, reactivate access keys.
  --password PASSWORD   Supply password, do not require user to reset.
  --email EMAIL         Supply user's email address for sending credentials.
  -h, --help            Show this help message and exit.
  -v, --verbose         Log to activity to STDOUT at log level INFO.
  -d, --debug           Increase log level to 'DEBUG'. Implies '--verbose'.
  --boto-log            Include botocore and boto3 logs in log stream.
  

"""

import os
import sys

import boto3
from botocore.exceptions import ClientError
import yaml
import logging
import docopt
from docopt import docopt
from passgen import passgen

from awsorgs.utils import *

"""
TODO:
modify utils.get_logger() so it does not require 'report' '--exec' param
disable/reenable ssh keys



email user
  validate sms service
  gather aws config profiles for user
  send email with
    user info
      user name
      account name
      account Id
      aws console login url
    instructions for credentials setup
      reset one-time pw
      create access key
      mfa device
      populate ~/.aws/{credentials,config}
      upload ssh pubkey (optional)
    aws-shelltools usage
  send separate email with one-time pw

revoke one-time pw if older than 24hrs


"""


def prep_email(log, args, onetimepw):
    pass


def main():
    args = docopt(__doc__)

    # log level
    log_level = logging.CRITICAL
    if args['--verbose'] or args['--boto-log']:
        log_level = logging.INFO
    if args['--debug']:
        log_level = logging.DEBUG
    # log format
    log_format = '%(name)s: %(levelname)-9s%(message)s'
    if args['--debug']:
        log_format = '%(name)s: %(levelname)-9s%(funcName)s():  %(message)s'
    if not args['--boto-log']:
        logging.getLogger('botocore').propagate = False
        logging.getLogger('boto3').propagate = False
    logging.basicConfig(format=log_format, level=log_level)
    log = logging.getLogger(__name__)
    log.debug("%s: args:\n%s" % (__name__, args))

    iam = boto3.resource('iam')
    user = iam.User(args['USER'])
    try:
        user.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print('no such user: %s' % args['USER'])
            sys.exit(1)

    # check for user supplied passwd
    if args['--password']:
        passwd = args['--password']
        require_reset = False
    else:
        passwd = passgen()
        require_reset = True


    login_profile = user.LoginProfile()
    try:
        login_profile.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            if args['--new'] or args['--reenable']:
                # create login profile
                log.info('creating login profile for user %s' % user.name)
                login_profile = user.create_login_profile(
                        Password=passwd,
                        PasswordResetRequired=require_reset)
                prep_email(log, args, passwd)
            else:
                print "User '%s' has no login profile" % args['USER']
                sys.exit(0)

    if args['--reset']:
        # update login profile with new passwd
        log.info('updating passwd for user %s' % user.name)
        onetimepw = passgen()
        login_profile.update(
                Password=passwd,
                PasswordResetRequired=require_reset)
        prep_email(log, args, passwd)

    elif args['--disable']:
        # delete login profile
        log.info('disabling login profile for user %s' % user.name)
        login_profole.delete()
        # deactivate access keys
        for key in user.access_keys.all():
            key.deactivate()

    elif args['--reenable']:
        # reactivate access keys
        log.info('reenabling access keys for user %s' % user.name)
        for key in user.access_keys.all():
            key.activate()

    else:
        print 'User:                  %s' % user.name
        print 'Id:                    %s' % user.user_id
        print 'create_date:           %s' % user.create_date
        print 'password_last_used:    %s' % user.password_last_used
        print 'profile create date    %s' % login_profile.create_date
        print 'Passwd reset required: %s' % login_profile.password_reset_required


if __name__ == "__main__":
    main()
