IAM User Login Profiles - ``awsloginprofile``
=============================================

Prerequisites:

- admin access to auth account
- spec file setup

  - ~/.awsorgs/config.yaml for awsorgs configuration parameters
  - spec files in spec_dir directory which is defined in config.yaml
  - create at least one satelite account (see awsaccounts)


Commands used:

- awsauth users --exec
- awsloginprofile user --new
- awsloginprofile user --reset
- awsloginprofile user --report


spec files impacted:

- ~/.awsorgs/config.yaml
- spec_dir/users.yaml
- spec_dir/groups.yaml


Actions Summary:

- `Define org_access_role in ~/.awsorgs/config.yaml`_
- `Assume OrgAdmin role for creating new IAM user`_
- `Check current user login profile`_
- `Create new IAM user in users.yaml and groups.yaml`_
- `Create new IAM user with awsauth`_
- `Create user login profile with awsloginprofile`_
- `User will receive initial login instruction from email notification`_
- `Check user login status`_
- `Reset user login profile(password)`_



Define org_access_role in ``~/.awsorgs/config.yaml``
****************************************************

Edit ~/.awsorgs/config.yaml ::

  org_access_role: awsauth/OrgAdmin



Assume ``OrgAdmin`` role for creating new IAM user
**************************************************

Assume auth acount administrtor role::

  (py36) [jhsu@scrappy-aws awsorgs]$ aws-assume-role master-abc-OrgAdmin
  (py36) [jhsu@scrappy-aws awsorgs]$
  (py36) [jhsu@scrappy-aws awsorgs]$ aws-whoami
  {
    "UserId": "AROAJS2JVTC6CC3YZX3BC:abc-admin@OrgAdmin",
    "Account": "123456789011",
    "Arn": "arn:aws:sts::123456789011:assumed-role/OrgAdmin/abc-admin@OrgAdmin"
  }



Check current user login profile
********************************

Run 'awsloginprofile user' ::

  (py36) [jhsu@scrappy-aws awsorgs]$ awsloginprofile abcaws1-user-1
  User:                   abcaws1-user-1
  Arn:                    arn:aws:iam::123456789011:user/awsauth/abcaws1-user-1
  User Id:                AIDAI5DX7YNIPTLGTQXZK
  User created:           2019-01-03 01:28:59+00:00
  Login profile created:  2019-01-10 19:32:11+00:00
  Passwd reset required:  True
  Password last used:     2019-01-10 19:55:35+00:00
  Delegations:
    Account Id      Alias                   Role
    2222222222      acct-abcaws1          awsauth/abcaws1


  (py36) [jhsu@scrappy-aws awsorgs]$ awsloginprofile abcaws1-user-2
  no such user: abcaws1-user-2



Create new IAM user in ``users.yaml`` and ``groups.yaml``
*********************************************************

Edit users.yaml ::
  
  - Name: abcaws1-user-2
    Email: xyz@yahoo.com
    Team: team-abcaws1

Edit groups.yaml ::

  - Name: group-abcaws1
    Members:
      - abcaws1-user-1
      - abcaws1-user-2



Create new IAM user with ``awsauth``
************************************

Run 'awsauth users --exec' ::

  (py36) [jhsu@scrappy-aws awsorgs]$ awsauth users  --exec
  awsorgs.utils: INFO     Creating user 'abcaws1-user-2'
  awsorgs.utils: INFO     arn:aws:iam::123456789011:user/awsauth/abcaws1-user-2
  awsorgs.utils: INFO     Adding user 'abcaws1-user-2' to group 'all-users'
  awsorgs.utils: INFO     Adding user 'abcaws1-user-2' to group 'group-abcaws1'



Create user login profile with ``awsloginprofile``
**************************************************

Run 'wsloginprofile user --new' ::

  (py36) [jhsu@scrappy-aws awsorgs]$ awsloginprofile abcaws1-user-2 --new



User will receive initial login instruction from email notification
*******************************************************************

Check email titled "login profile" for initial AWS login instruction ::

  Dear User,

  You have been granted access to our central AWS authentication account.  From here you can assume designated roles into other AWS accounts in our Organization.

  You must complete the following tasks to configure your access:

  1) Use the credentials below to log into the AWS console.  You will be required to change your password as you log in.  The rules for good passwords are as follows:

  - Minimum password length: 8
  - Require at least one uppercase character from Latin alphabet. (A-Z)
  - Require at least one lowercase character from Latin alphabet. (a-z)
  - Require at least one symbol. (!@#$%^&amp;*()_+-=[]{}|')
  - Require at least one number. (0-9)

  IMPORTANT: your one time password will expire after 24 hours.

  IAM User Name:        abcaws1-user-2
  One Time Password:    Stroller_Ochre+402_Disputed
  Login URL:            https://master-aaa.signin.aws.amazon.com/console



Check user login status
***********************

Run 'wsloginprofile user' ::

  (py36) [jhsu@scrappy-aws awsorgs]$ awsloginprofile abcaws1-user-2

  User:                   abcaws1-user-2
  Arn:                    arn:aws:iam::123456789011:user/awsauth/abcaws1-user-2
  User Id:                AIDAJKHIBNEWTQ3T2QOYC
  User created:           2019-01-15 00:06:45+00:00
  Login profile created:  2019-01-15 00:07:08+00:00
  Passwd reset required:  False
  Password last used:     2019-01-15 00:51:46+00:00
  Delegations:
    Account Id      Alias                   Role
    222222222222    acct-abcaws1          awsauth/abcaws1


Reset user login profile(password)
**********************************

Run 'wsloginprofile user --reset' ::

  awsloginprofile abcaws1-user-2 --reset




