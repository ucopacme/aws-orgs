========
aws-orgs
========

This project is an attempt to provision AWS Oranizations IAM resources
based on structured imput files.

aws-orgs installation provides three python executibles:  

awsorgs
  Manage recources in an AWS Organization.

awsaccounts
  Manage accounts in an AWS Organization.

awsorgaccessrole
  Generate default org access role in an invited account.

awsauth
  Manage users, group, and roles for cross account access in an 
  AWS Organization.

awsloginprofile
  Manage AWS IAM user login profile.


Run each of these with the '--help' option for usage documentation.

See the ``samples/`` directory for anotated examples of spec-file syntax.


**Install**

Site installation::

  sudo pip install git+https://www.github.com/ashleygould/aws-orgs.git 

Local user installation::

  git clone https://github.com/ashleygould/aws-orgs
  pip install --user -e aws-orgs/

On RHEL6 you may need to update setuptools as well:

  sudo pip install -U setuptools



**Uninstall**::

  pip uninstall aws-orgs

  # if installed as local user also run:
  rm ~/.local/bin/{awsorgs,awsaccounts,awsauth}


**Usage**::

  # Run each command with -h option for full usage info.

  awsorgs report
  awsorgs organization -v -s org-spec.yaml [--exec]

  awsaccounts report
  awsaccounts invite --account-id ID [--exec]
  awsaccounts create -v -s account-spec.yaml [--exec]

  awsorgs-accessrole --master_id ID [--exec]

  awsauth report -s auth-spec.yaml 
  awsauth users -v -s auth-spec.yaml [--exec]
  awsauth delegation -v -s auth-spec.yaml [--exec]

  awsloginprofile maryanne
  awsloginprofile maryanne --new --role ListOrgAccounts
  awsloginprofile maryanne --reset --role ListOrgAccounts
  awsloginprofile maryanne --disable
  awsloginprofile maryanne --reenable
  awsloginprofile maryanne --disable-expired --opt-ttl 48



:Author:
    Ashley Gould (agould@ucop.edu)

:Version: 0.0.6.rc1

