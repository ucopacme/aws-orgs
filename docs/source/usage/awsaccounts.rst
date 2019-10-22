Provissioning Accounts - ``awsaccounts``
========================================

Prerequisites:

- admin access to auth account
- spec file setup

  - ``~/.awsorgs/config.yaml`` for awsorgs configuration parameters
  - spec files in ``spec_dir`` directory which is defined in ``config.yaml``
  - create at least one satelite account (see ``awsaccounts``)



Commands used:

- awsaccounts report
- awsaccounts create
- awsaccounts create --exec
- awsaccounts update
- awsaccounts update --exec


Spec files impacted:

- ~/.awsorgs/config.yaml
- spec_dir/accounts.yaml


Actions Summary:

- `Report accounts in an AWS Organization`_
- `Create a new AWS account`_
- `Set or update AWS account alias`_
- `Set or update AWS account tags`_



Report accounts in an AWS Organization
**************************************

Run ``awsaccount report``::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts report

  _______________________
  Active Accounts in Org:

  Name:               Alias               Id:             Email:
  account-abcaws1   acct-abcaws1      123456789011    mail1@yahoo.com
  account-abcaws2   acct-abcaws2      123456789011    mail2@yahoo.com
  account-abcaws3   accnt-abcaws3     123456789011    mail3@yahoo.com



Create a new AWS account
************************

Edit file ``accounts.yaml``

Example Diff::

  ~/.awsorgs/spec.d> git diff account-tags 
  diff --git a/accounts.yaml b/accounts.yaml
  index 701d502..5224dc5 100644
  --- a/accounts.yaml
  +++ b/accounts.yaml
  @@ -72,3 +72,7 @@ accounts:
  +- Name: test3
  +  Email: test3@example.com
  +  Alias:
  +  Tags:

Review proposed changes in ``dry-run`` mode::

  $ awsaccounts create

Implement and review changes  **!!WARNING!! D0 NOT RUN WITH --exec IF DOING
FUNCTIONAL TESTING.  It is a pain to remove unwanted acounts.** ::  

  $ awsaccounts create --exec
  $ awsaccounts report



Set or update AWS account alias
*******************************

Edit file ``accounts.yaml``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/accounts.yaml b/accounts.yaml
  index 701d502..7f3bb83 100644
  --- a/accounts.yaml
  +++ b/accounts.yaml
  @@ -18,7 +18,7 @@ accounts:
   - Name: Managment
  -  Alias: ashely-managment
  +  Alias: central-auth
     Email: management@example.com
     Tags:


Review proposed changes in ``dry-run`` mode::

  $ awsaccounts update


Implement and review changes::

  $ awsaccounts update --exec
  $ awsaccounts report


Set or update AWS account tags
******************************

Edit file ``accounts.yaml``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/accounts.yaml b/accounts.yaml
  index 7f3bb83..9f3f0d3 100644
  --- a/accounts.yaml
  +++ b/accounts.yaml
  @@ -21,7 +21,8 @@ accounts:
     Alias: central-auth
     Email: management@ucop.edu
     Tags:
  -    owner: Ashley Gould
  +    owner: Kumar Yegamani
  +    service: infrastructure
       application: identity_mgmt
       environment: production

Review proposed changes in ``dry-run`` mode::

  $ awsaccounts update


Implement::


  $ awsaccounts update --exec

Review changes - assume role into master account::

  $ aws organizations list-tags-for-resource --resource-id <account_id>

