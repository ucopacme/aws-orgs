#!/usr/bin/env python
"""Generatate AWS IAM user login profile and notify user with useful
instructions how to get started.

Usage:
  awsloginprofile [-vd] USER [--new | --reset | --disable | --reenable]
                  [--password PASSWORD] [--email EMAIL] [--boto-log]
  awsloginprofile --help

Options:
  -h, --help            Show this help message and exit.
  USER                  Name of IAM user.
  --new                 Create new login profile.
  --reset               Reset password for existing login profile.
  --disable             Delete existing login profile, disable access keys.
  --reenable            Recreate login profile, reactivate access keys.
  --password PASSWORD   Supply password, do not require user to reset.
  --email EMAIL         Supply user's email address for sending credentials.
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
modify utils.get_logger() so it does not require 'report' param


if report
  list status of user

create login profile
  generate random pw
  validate user exists
  overwrite existing profile?

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




def main():
    args = docopt(__doc__)
    #log = get_logger(args)
    #log.debug("%s: args:\n%s" % (__name__, args))
    print("%s: args:\n%s" % (__name__, args))

    #iam = boto3.resource('iam')
    #user = iam.User(args['--user'])
    #print user
    #print user.password_last_used
    #login_profile = user.LoginProfile()
    #print login_profile

    #try:
    #    login_profile.load()
    #except ClientError as e:
    #    if e.response['Error']['Code'] == 'NoSuchEntity':
    #        # create login profile
    #        log.info('creating login profile for user %s' % user.name)
    #        onetimepw = passgen()
    #        print onetimepw
    #        login_profile = user.create_login_profile(
    #                Password=onetimepw,
    #                PasswordResetRequired=True)

    ##print type(login_profile.create_date)
    #print login_profile.create_date
    #print login_profile.password_reset_required

    #if args['--reset']:
    #    # update login profile with new passwd
    #    log.info('updating passwd for user %s' % user.name)
    #    onetimepw = passgen()
    #    print onetimepw
    #    result = login_profile.update(
    #            Password=onetimepw,
    #            PasswordResetRequired=True)
    #print result

    #if args['--disable']:
    #    # delete login profile
    #    log.info('deleting login profile for user %s' % user.name)
    #    result = login_profile.delete()
    #    for key in user.access_keys.all():
    #        key.deactivate()

    #print result




if __name__ == "__main__":
    main()
