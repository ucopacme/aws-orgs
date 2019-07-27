Users and Groups - ``awsauth users``
=====================================

Prerequisites:

- admin access to auth account
- spec file setup

  - install template spec files
  - spec files under git
  - site specific paramaters defined in common.yaml
  - configure ~.awsorgs/config.yaml
  - create at least one satelite account (see awsaccounts)


Commands used:

- git diff
- awsauth users
- awsauth users --exec
- awsauth report --users


Spec files impacted:

- users.yaml
- groups.yaml
- custom_policies.yaml


Actions Summary:

- `Report users and groups in all accounts`_
- `Create an IAM user and group, and add the user to the group`_
- `Attach a IAM managed policy to your group`_
- `Attach a IAM custom policy to your group`_
- `Modify attached custom policy`_
- `Detach policies, users from group`_
- `Delete group, delete users`_



Report users and groups in all accounts
***************************************

Run ``awsauth report`` command with ``--users`` flag::

  $ awsauth report --users 
  _________________________________________
  IAM Users and Groups in all Org Accounts:
  _____________________
  Account:    Managment
  Users:
  - arn:aws:iam::123456789011:user/awsauth/sysadm/agould
  - arn:aws:iam::123456789011:user/awsauth/drivera
  - arn:aws:iam::123456789011:user/awsauth/jhsu
  
  Groups:
  - arn:aws:iam::123456789011:group/awsauth/all-users
  - arn:aws:iam::123456789011:group/awsauth/orgadmins
  
  ____________________
  Account:    blee-dev
  ____________________
  Account:    blee-poc
  _____________________
  Account:    blee-prod
  __________________
  Account:    master
  Users:
  - arn:aws:iam::222222222222:user/agould
  
  Groups:
  - arn:aws:iam::222222222222:group/Admins


Some variations::

  $ awsauth report --users --full --account Managment
  $ awsauth report --users --full
  $ awsauth report --credentials --account Managment
  $ awsauth report --credentials



Create an IAM user and group, and add the user to the group
***********************************************************

Edit the following files:

- users.yaml 
- groups.yaml 

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/groups.yaml b/groups.yaml
  index 7f37144..d3fe879 100644
  --- a/groups.yaml
  +++ b/groups.yaml
  @@ -46,3 +46,8 @@ groups:

  +  - Name: testers
  +    Ensure: present
  +    Members:
  +      - joeuser
  +      - maryuser
  diff --git a/users.yaml b/users.yaml
  index 22d2d61..5424bf4 100644
  --- a/users.yaml
  +++ b/users.yaml
  @@ -36,3 +36,6 @@ users:

  +  - Name: joeuser
  +    Email: joeuser@example.com
  +    Team: test
  +  - Name: maryuser
  +    Email: maryuser@example.com
  +    Team: test

Review proposed changes in ``dry-run`` mode::

  $ awsauth users

Implement and review changes::  

  $ awsauth users --exec
  $ awsauth report --users


Attach a IAM managed policy to your group
*****************************************

Edit file ``groups.yaml``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/groups.yaml b/groups.yaml
  index d3fe879..9e05738 100644
  --- a/groups.yaml
  +++ b/groups.yaml
  @@ -50,4 +50,6 @@ groups:
     - Name: testers
       Ensure: present
       Members:
         - joeuser
         - maryuser
  +    Policies:
  +      - IAMReadOnlyAccess

Review proposed changes in ``dry-run`` mode::

  $ awsauth users

Implement and review changes::  

  $ awsauth users --exec
  $ aws iam list-attached-group-policies  --group-name testers


Attach a IAM custom policy to your group
****************************************

Edit the following files:

- groups.yaml 
- custom_policies.yaml 

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/custom_policies.yaml b/custom_policies.yaml
  index da46ebb..5d411f0 100644
  --- a/custom_policies.yaml
  +++ b/custom_policies.yaml
  @@ -111,3 +111,14 @@ custom_policies:
           Action:
             - aws-portal:Account*
           Resource: '*'
  +
  +  - PolicyName: ReadS3Bucket
  +    Description: list and get objects from my s3 bucket
  +    Statement:
  +      - Effect: Allow
  +        Action:
  +          - s3:List*
  +          - s3:Get*
  +        Resource:
  +          - arn:aws:s3:::my_bucket
  +          - arn:aws:s3:::my_bucket/*
  diff --git a/groups.yaml b/groups.yaml
  index b506856..11e87cb 100644
  --- a/groups.yaml
  +++ b/groups.yaml
  @@ -36,3 +36,4 @@ groups:
         - maryuser
       Policies:
         - IAMReadOnlyAccess
  +      - ReadS3Bucket


Review proposed changes in ``dry-run`` mode::

  $ awsauth users

Implement and review changes::  

  $ awsauth users --exec
  $ aws iam list-attached-group-policies  --group-name testers
  $ aws iam get-policy --policy-arn <your_policy_arn>


Modify attached custom policy
*****************************

Edit file ``custom_policies.yaml``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/custom_policies.yaml b/custom_policies.yaml
  index d6f29d7..7f5748a 100644
  --- a/custom_policies.yaml
  +++ b/custom_policies.yaml
  @@ -131,6 +131,8 @@ custom_policies:
           Resource:
             - arn:aws:s3:::my_bucket
             - arn:aws:s3:::my_bucket/*
  +          - arn:aws:s3:::my_other_bucket
  +          - arn:aws:s3:::my_other_bucket/*


Review proposed changes in ``dry-run`` mode::

  $ awsauth users

Implement and review changes::  

  $ awsauth users --exec
  $ aws iam list-attached-group-policies  --group-name testers
  $ aws iam get-policy --policy-arn <your_policy_arn>
  $ aws iam get-policy-version --policy-arn <your_policy_arn> --version-id <version_id>


Detach policies, users from group
*********************************

Edit the following files:

- groups.yaml 

Example Diff::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups.yaml b/groups.yaml
  index 9e05738..565b1ab 100644
  --- a/groups.yaml
  +++ b/groups.yaml
  @@ -49,7 +49,4 @@ groups:
     - Name: testers
       Ensure: present
       Members:
  -      - joeuser
  -      - maryuser
       Policies:
  -      - IAMReadOnlyAccess
  -      - ReadS3Bucket


Review proposed changes in ``dry-run`` mode::

  $ awsauth users

Implement and review changes::  

  $ awsauth users --exec
  $ awsauth report --users
  $ aws iam list-attached-group-policies  --group-name testers
  $ aws iam get-policy --policy-arn <your_policy_arn>


Delete group, delete users
**************************

Files to edit:

- users.yaml
- groups.yaml

To delete IAM entities we must set attribute ``Ensure: absent`` to associated spec.

Example diff::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups.yaml b/groups.yaml
  index 9e05738..4eda72b 100644
  --- a/groups.yaml
  +++ b/groups.yaml
  @@ -47,9 +47,6 @@ groups:

     - Name: testers
  -    Ensure: present
  +    Ensure: absent
       Members:
       Policies:
  diff --git a/users.yaml b/users.yaml
  index 5424bf4..3e8b87d 100644
  --- a/users.yaml
  +++ b/users.yaml
  @@ -37,5 +37,6 @@ users:
     - Name: joeuser
  +    Ensure: absent
       Email: joeuser@example.com
       Team: test
     - Name: maryuser
  +    Ensure: absent
       Email: maryuser@example.com
       Team: test


Review proposed changes in ``dry-run`` mode::

  $ awsauth users

Implement and review changes::  

  $ awsauth users --exec
  $ awsauth report --users
