#!/usr/bin/python

"""Manage recources in an AWS Organization.

Usage:
  awsorgs.py report [--verbose] [--log-target <target>]...
  awsorgs.py (organization | accounts) (--spec-file FILE) [--exec] [--verbose]
             [--log-target <target>]...
  awsorgs.py (-h | --help)
  awsorgs.py --version

Modes of operation:
  report         Display organization status report only.
  orgnanizaion   Run AWS Org management tasks per specification.
  accounts       Create new accounts in AWS Org per specifation.

Options:
  -h, --help                 Show this help message and exit.
  --version                  Display version info and exit.
  -s FILE, --spec-file FILE  AWS Org specification file in yaml format.
  --exec                     Execute proposed changes to AWS Org.
  -l, --log-target <target>  Where to send log output.  This option can be
                             Repeated to specicy multiple targets.
  -v, --verbose              Log to STDOUT as well as log-target.

Supported log targets:
  local file:       /var/log/orgs.out
  email addresses:  agould@blee.red
  AWS sns stream:   ??syntax??
  

"""


import boto3
from docopt import docopt
if __name__ == '__main__':
    args = docopt(__doc__, version='awsorgs 0.0.0')
    print args

#  --make-report         display organization status report only
#  --make-org            run AWS Org management tasks per specification
#  --make-account        create new accounts in AWS Org per specifation

             #[--verbose] [--log-target (STDOUT | FILE | EMAIL | SNS)]
  #--log-target          where to send log output [default: STDOUT]
  #awsorgs.py (--make-org | --make-account) (--spec-file FILE) [--exec] [--verbose]
  #awsorgs.py (--make-org | --make-account) (--spec-file FILE) [--exec] [--verbose] [--log-target (STDOUT | FILE | EMAIL | SNS)]
