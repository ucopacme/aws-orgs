IAM Service Users - ``awsauth local-users``
===========================================

Prerequisites:

- custom policy to attach to service user.


Commands used:

- git diff
- awsauth local-users
- awsauth local-users --exec
- awsauth report --users


Spec files impacted:

- :ref:`example_spec_files:local_users.yaml`
- :ref:`example_spec_files:custom_policies.yaml`


Actions Summary:

- `Create an IAM Service user`
- `Modify attached custom policy`
- `Delete an IAM Service user`


Create an IAM Service user
**************************

Edit the following files:

- local_users.yaml 

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/local_users.yaml b/local_users.yaml
  index 2e2521b..6858c36 100644
  --- a/local_users.yaml
  +++ b/local_users.yaml
  @@ -29,6 +29,15 @@ local_users:
     Account: All
     Policies:
     - ReadOnlyAccess
  +- Name: ses-smtp-user-myapp
  +  Description: Local service user for SES SMTP access
  +  Team: myapp
  +  Path: service
  +  Account:
  +  - myapp-build
  +  - myapp-prod
  +  Policies:
  +  - AmazonSesSendingAccess


Review proposed changes in ``dry-run`` mode::

  $ awsauth local-users

Implement and review changes::  

  $ awsauth local-users --exec
  $ awsauth report --users


Modify attached custom policy
*****************************

See :ref:`modify_custom_policy`



Delete an IAM Service user
**************************

Files to edit:

- local-users.yaml

To delete IAM entities we must set attribute ``Ensure: absent`` to associated spec.

Example diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/local-users.yaml b/local-users.yaml
  index 6858c36..3c89841 100644
  --- a/local_users.yaml
  +++ b/local_users.yaml
  @@ -30,6 +30,7 @@ local_users:
     Policies:
     - ReadOnlyAccess
   - Name: ses-smtp-user-myapp
  +  Ensure: absent
     Description: Local service user for SES SMTP access
     Team: myapp
     Path: service



Review proposed changes in ``dry-run`` mode::

  $ awsauth local-users

Implement and review changes::  

  $ awsauth local-users --exec
  $ awsauth report --users


