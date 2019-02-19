Functional tests for awsorgs/awsaccounts
========================================

Prerequisites:

- admin access to auth account
- spec file setup

  - ~/.awsorgs/config.yaml for awsorgs configuration parameters
  - spec files in spec_dir directory which is defined in config.yaml
  - create at least one satelite account (see awsaccounts)



AWS account alias
-----------------

Commands used:

- awsaccounts alias
- awsaccounts alias --exec
- awsaccounts report


spec files impacted:

- ~/.awsorgs/config.yaml
- spec_dir/account-spec.yml


Actions Summary:

- Define org_access_role in ~/.awsorgs/config.yaml
- Define spec_dir/accoount-spec.yml
- awsaccoutns alias 
- awsaccoutns alias --exec
- awsaccoutns report



Define org_access_role in ~/.awsorgs/config.yaml
************************************************

Edit ~/.awsorgs/config.yaml ::

  org_access_role: OrganizationAccountAccessRole



Show current awsaccoutns alias
******************************

Run 'awsacccouns report' ::

  (py36) [jhsu@scrappy-aws ~]$ awsaccounts report

  _______________________
  Active Accounts in Org:

  Name:               Alias               Id:             Email:
  account-abcaws1   acct-abcaws1      123456789011    mail1@yahoo.com
  account-abcaws2   acct-abcaws2      123456789011    mail2@yahoo.com
  account-abcaws3   acct-abcaws3      123456789011    mail3@yahoo.com



Edit spec_dir/accoount-spec.yml
*******************************

Change account-abcaws3 alias from acct-abcaws3 to accnt-abcaws3::

  - Name: account-abcaws3
  Team: team-abcaws3
  Alias: accnt-abcaws3
  Email: mail3@yahoo.com



Dryrun awsaccounts alias
************************

Run 'awsaccount alias' ::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts alias

  [dryrun] awsorgs.utils: INFO     resetting account alias for account 'account-abcaws3' to 'accnt-abcaws3'; previous alias was 'acct-abcaws3'



Exec awsaccounts alias
**********************

Run 'awsaccount alias --exec' ::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts alias --exec

  awsorgs.utils: INFO     resetting account alias for account 'account-abcaws3' to 'accnt-abcaws3'; previous alias was 'acct-abcaws3'



awsaccounts report
******************

Run 'awsaccount report' ::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts report


  _______________________
  Active Accounts in Org:

  Name:               Alias               Id:             Email:
  account-abcaws1   acct-abcaws1      123456789011    mail1@yahoo.com
  account-abcaws2   acct-abcaws2      123456789011    mail2@yahoo.com
  account-abcaws3   accnt-abcaws3     123456789011    mail3@yahoo.com





