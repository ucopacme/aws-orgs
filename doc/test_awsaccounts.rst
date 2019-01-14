Functional tests for awsorgs/awsaccounts
========================================

Prerequisites:

- admin access to auth account
- spec file setup

  - ~/.awsorgs/config.yaml for awsorgs configuration parameters
  - spec files in spec_dir directory which is defined in config.yaml
  - create at least one satelite account (see awsaccounts)



AWS account alias  - ``awsaccounts alias``
------------------------------------------

Commands used:

- awsaccounts alias
- awsaccounts alias --exec
- awsaccounts report


spec files impacted:

- ~/.awsorgs/config.yaml
- spec_dir/account-spec.yml


Actions Summary:

- Define org_access_role in ~/.awsorgs/config.yaml
- Define spec_dir/accoounts.yml
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
  account-jjhsuaws1   acct-jjhsuaws1      938960831554    mail1@yahoo.com
  account-jjhsuaws2   acct-jjhsuaws2      427989285695    mail2@yahoo.com
  account-jjhsuaws3   acct-jjhsuaws3      409058358936    mail3@yahoo.com



Edit spec_dir/accoounts.yml
***************************

Change account-jjhsuaws3 alias from acct-jjhsuaws3 to accnt-jjhsuaws3::

  - Name: account-jjhsuaws3
  Team: team-jjhsuaws3
  Alias: accnt-jjhsuaws3
  Email: mail3@yahoo.com



Dryrun awsaccounts alias
************************

awsaccount alias ::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts alias

  [dryrun] awsorgs.utils: INFO     resetting account alias for account 'account-jjhsuaws3' to 'accnt-jjhsuaws3'; previous alias was 'acct-jjhsuaws3'



Exec awsaccounts alias
**********************

awsaccount alias --exec ::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts alias --exec

  awsorgs.utils: INFO     resetting account alias for account 'account-jjhsuaws3' to 'accnt-jjhsuaws3'; previous alias was 'acct-jjhsuaws3'



awsaccounts report
******************

awsaccount report ::

  (py36) [jhsu@scrappy-aws doc]$ awsaccounts report


  _______________________
  Active Accounts in Org:

  Name:               Alias               Id:             Email:
  account-jjhsuaws1   acct-jjhsuaws1      938960831554    mail1@yahoo.com
  account-jjhsuaws2   acct-jjhsuaws2      427989285695    mail2@yahoo.com
  account-jjhsuaws3   accnt-jjhsuaws3      409058358936    mail3@yahoo.com





