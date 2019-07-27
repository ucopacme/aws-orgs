Getting started with aws-orgs
=============================

A configuration management tool set for AWS Organizations.

Full documentation is available at https://aws-orgs.readthedocs.io/en/latest


Features
--------

- Ensure state of AWS Organizations and IAM resourses per `yaml`_ formatted 
  specification files.
- Configure AWS Organizations resources:

  - organizational units
  - service control policies
  - account creation and organizational unit placement

- Centrally manage IAM access across AWS Organization accounts:

  - IAM users/groups in a central *Auth* account
  - customer managed IAM policies
  - IAM roles and trust delegation in organization accounts




Installation
------------

Python virtual environment (recommended)::

  source ~/path_to_my_venv/bin/activate
  pip install aws-orgs


Editable copy in venv::

  git clone https://github.com/ucopacme/aws-orgs
  pip install -e aws-orgs/


Uninstall::

  pip uninstall aws-orgs


Configuration quick start
-------------------------

Run the ``awsorgs-spec-init`` script to generate an initial set of spec-files::

  awsorgs-spec-init

This generates an initial ``config.yaml`` spec files under ``~/.awsorgs``.  Edit
these as needed to suit your environment.

See ``--help`` option for full usage.



Console Scripts
---------------

``aws-orgs`` provides the following python executibles:  

awsorgs
  Manage recources in an AWS Organization.

awsaccounts
  Manage accounts in an AWS Organization.

awsauth
  Manage users, group, and roles for cross account access in an 
  AWS Organization.

awsloginprofile
  Manage AWS IAM user login profile.


All commands execute in ``dry-run`` mode by default.  Include the ``--exec``
flag to affect change to AWS resources.  Run each of these with the '--help'
option for usage documentation.

::

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

:Version: 0.3.0




.. references

.. _yaml: https://yaml.org/
