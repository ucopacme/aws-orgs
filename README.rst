aws-orgs
========

This project is an attempt to provision AWS Oranizations IAM resources
based on structured imput files.

aws-orgs installation provides the following python executibles:  

awsorgs
  Manage recources in an AWS Organization.

awsaccounts
  Manage accounts in an AWS Organization.

awsorg-accessrole
  Generate default org access role in an invited account.

awsauth
  Manage users, group, and roles for cross account access in an 
  AWS Organization.

awsloginprofile
  Manage AWS IAM user login profile.


Run each of these with the '--help' option for usage documentation.

See the ``samples/`` directory for anotated examples of spec-file syntax.


Installation
------------

Python virtual environment (recommended)::

  source ~/path_to_my_venv/bin/activate
  pip install https://github.com/ucopacme/aws-orgs/archive/master.zip


Editable copy in venv::

  git clone https://github.com/ucopacme/aws-orgs
  pip install -e aws-orgs/

Local user installation::

  git clone https://github.com/ucopacme/aws-orgs
  pip install --user -e aws-orgs/


Uninstall::

  pip uninstall aws-orgs

  # if installed as local user also run:
  rm ~/.local/bin/{awsorgs,awsaccounts,awsauth}


Configuration
-------------

Copy example spec files into your `spec_dir` location and edit as appropriate
to your site.  The default spec directory is `~/.awsorgs/spec.d`.

Most CLI commands make use of a config file for basic paramaters.  
The default location is `~/.awsorgs/config.yaml`.  Example::

  # Path to yaml spec files directory.  Any yaml files under this 
  # dirctory (recursive) are parsed as spec files.
  spec_dir: ~/git-repos/awsorgs_specfiles/my_org
  
  # An AWS role name which permits cross account access to all accounts.
  org_access_role: awsauth/OrgAdmin
  
  # AWS account Id for the Organization master account.  This must be in quotes.
  master_account_id: '121212121212'
  
  # AWS account Id for the Central Auth account.  This must be in quotes.
  auth_account_id: '343434343434'



Usage
-----

Run each command with -h option for full usage info::

  awsorgs report
  awsorgs organization
  awsorgs organization --exec

  awsaccounts report
  awsaccounts create [--exec]
  awsaccounts alias [--exec]

  awsaccounts invite --account-id ID [--exec]
  # from invited account:
  awsorgs-accessrole --master_id ID [--exec]

  awsauth report
  awsauth report --users
  awsauth report --delegations
  awsauth report --credentials --full
  awsauth report --account ucpath-prod --users --full

  awsauth users [--exec]
  awsauth delegations [--exec]
  awsauth local-users [--exec]

  awsloginprofile maryanne
  awsloginprofile maryanne --new
  awsloginprofile maryanne --reset
  awsloginprofile maryanne --disable-expired --opt-ttl 48



:Author:
    Ashley Gould (agould@ucop.edu)

:Version: 0.0.11

