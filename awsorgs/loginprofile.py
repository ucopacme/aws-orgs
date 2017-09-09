#!/usr/bin/env python
"""Manage AWS IAM user login profile.

Usage:
  awsloginprofile USER [-vd] [--boto-log]
  awsloginprofile USER --disable [-vd] [--boto-log]
  awsloginprofile USER (--new | --reset | --reenable) [-vd] [--boto-log]
                       [--password PASSWORD] [--email EMAIL]
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
import yaml
import logging

import boto3
from botocore.exceptions import ClientError
import docopt
from docopt import docopt
from passgen import passgen

from awsorgs.utils import *

"""
TODO:
disable/reenable ssh keys
revoke one-time pw if older than 24hrs
prep_email()
send_email()

"""


def prep_email(log, args, passwd, email):
    """
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
    """
    pass


def validate_user(user_name):
    iam = boto3.resource('iam')
    user = iam.User(user_name)
    try:
        user.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return    
    return user


def validate_login_profile(user):
    login_profile = user.LoginProfile()
    try:
        login_profile.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return
    return login_profile


def munge_passwd(passwd=None):
    # check for user supplied passwd
    if passwd:
        require_reset = False
    else:
        passwd = passgen()
        require_reset = True
    return passwd, require_reset


def create_profile(log, user, passwd, require_reset):
    # create login profile
    log.info('creating login profile for user %s' % user.name)
    return user.create_login_profile(
            Password=passwd,
            PasswordResetRequired=require_reset)


def update_profile(log, user, login_profile, passwd, require_reset):
    # update login profile with new passwd
    if login_profile:
        log.info('updating passwd for user %s' % user.name)
        return login_profile.update(
                Password=passwd,
                PasswordResetRequired=require_reset)
    else:
        log.error("user '%s' has no login profile" % user.name)
        sys.exit(1)

def disable_profile(log, user, login_profile):
    # delete login profile
    if login_profile:
        log.info('deleting login profile for user %s' % user.name)
        login_profile.delete()
    else:
        log.warn("user '%s' has no login profile" % user.name)


def enable_access_keys(log, user, enable=True):
    for key in user.access_keys.all():
        if enable and key.status == 'Inactive':
            log.info('enabling access key %s for user %s' %
                    (key.access_key_id, user.name))
            key.activate()
        elif not enable and key.status == 'Active':
            log.info('disabling access key %s for user %s' %
                    (key.access_key_id, user.name))
            key.deactivate()


def user_report(log, user, login_profile):
    log.info('User:                  %s' % user.name)
    log.info('User Id:               %s' % user.user_id)
    log.info('User created:          %s' % user.create_date)
    if login_profile:
        log.info('User login profile:    %s' % login_profile.create_date)
        log.info('Password last used:    %s' % user.password_last_used)
        log.info('Passwd reset required: %s' % login_profile.password_reset_required)
    else:
        log.info('User login profile:    %s' % login_profile)


def main():
    args = docopt(__doc__)
    # HACK ALERT! add unused args to make get_logger() happy
    args['--exec'] = False
    args['report'] = True
    log = get_logger(args)

    user = validate_user(args['USER'])
    if not user:
        log.critical('no such user: %s' % args['USER'])
        sys.exit(1)

    login_profile = validate_login_profile(user)
    passwd, require_reset = munge_passwd(args['--password'])

    if args['--new']:
        if not login_profile:
            login_profile = create_profile(log, user, passwd, require_reset)
            prep_email(log, user, passwd, args['--email'])
        else:
            log.warn("login profile for user '%s' already exists" % user.name)
        if args['--verbose']:
            user_report(log, user, login_profile)

    elif args['--reset']:
        login_profile = update_profile(log, user, login_profile, passwd, require_reset)
        prep_email(log, user, passwd, args['--email'])
        if args['--verbose']:
            user_report(log, user, login_profile)

    elif args['--disable']:
        disable_profile(log, user, login_profile)
        enable_access_keys(log, user, False)
        if args['--verbose']:
            user_report(log, user, login_profile)

    elif args['--reenable']:
        if not login_profile:
            login_profile = create_profile(log, user, passwd, require_reset)
            prep_email(log, user, passwd, args['--email'])
        enable_access_keys(log, user, True)
        if args['--verbose']:
            user_report(log, user, login_profile)

    else:
        user_report(log, user, login_profile)


if __name__ == "__main__":
    main()
