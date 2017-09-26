#!/usr/bin/env python
"""Generate default org access role in newly joined account.

Usage:
  orgaccessrole --help
  orgaccessrole --master_id ID [--exec]

Options:
  -h, --help            Show this help message and exit.
  -m, --master_id ID    Master Account ID
"""

import os
import sys
import yaml
import json

import boto3
import botocore.exceptions
from botocore.exceptions import ClientError
import docopt
from docopt import docopt

import awsorgs.utils
from awsorgs.utils import *

ROLENAME = 'OrganizationAccountAccessRole'
DESCRIPTION = 'Organization Access Role'
POLICYNAME = 'AdministratorAccess'

def main():
    args = docopt(__doc__)

    iam_client = boto3.client('iam')

    principal = "arn:aws:iam::%s:root" % args['--master_id']
    statement = dict(
            Effect='Allow',
            Principal=dict(AWS=principal),
            Action='sts:AssumeRole')
    policy_doc = json.dumps(dict(
            Version='2012-10-17', Statement=[statement]))

    print("Creating role %s" % ROLENAME)
    if args['--exec']:
        iam_client.create_role(
                Description=DESCRIPTION,
                RoleName=ROLENAME,
                AssumeRolePolicyDocument=policy_doc)

    aws_policies = iam_client.list_policies(Scope='AWS',
            MaxItems=500)['Policies']
    policy_arn = lookup(aws_policies, 'PolicyName', POLICYNAME, 'Arn')

    iam_resource = boto3.resource('iam')
    role = iam_resource.Role(ROLENAME)
    try:
        role.load()
    except:
        pass
    else:
        print("Attaching policy %s to %s" % (POLICYNAME, ROLENAME))
        if args['--exec'] and policy_arn:
            role.attach_policy(PolicyArn=policy_arn)


if __name__ == "__main__":
    main()
