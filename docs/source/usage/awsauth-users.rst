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

- users-spec.yml
- groups-spec.yml
- custom-policy-spec.yml


Actions Summary:

- report IAM users and groups in accounts
- create an IAM user and group, and add the user to the group
- attach a IAM managed policy to your group
- attach a IAM custom policy to your group
- modify attached custom policy
- detach policies, users from group
- delete group, delete user



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

- users-spec.yml 
- groups-spec.yml 

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index 7f37144..d3fe879 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
  @@ -46,3 +46,8 @@ groups:

  +  - Name: testers
  +    Ensure: present
  +    Members:
  +      - joeuser
  +      - maryuser
  diff --git a/users-spec.yml b/users-spec.yml
  index 22d2d61..5424bf4 100644
  --- a/users-spec.yml
  +++ b/users-spec.yml
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

Edit file ``groups-spec.yml``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index d3fe879..9e05738 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
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

- groups-spec.yml 
- custom-policy-spec.yml 

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/custom-policy-spec.yml b/custom-policy-spec.yml
  index da46ebb..5d411f0 100644
  --- a/custom-policy-spec.yml
  +++ b/custom-policy-spec.yml
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
  diff --git a/groups-spec.yml b/groups-spec.yml
  index b506856..11e87cb 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
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

Edit file ``custom-policy-spec.yml``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/custom-policy-spec.yml b/custom-policy-spec.yml
  index d6f29d7..7f5748a 100644
  --- a/custom-policy-spec.yml
  +++ b/custom-policy-spec.yml
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

- groups-spec.yml 

Example Diff::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index 9e05738..565b1ab 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
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

- users-spec.yml
- groups-spec.yml

To delete IAM entities we must set attribute ``Ensure: absent`` to associated spec.

Example diff::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index 9e05738..4eda72b 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
  @@ -47,9 +47,6 @@ groups:

     - Name: testers
  -    Ensure: present
  +    Ensure: absent
       Members:
       Policies:
  diff --git a/users-spec.yml b/users-spec.yml
  index 5424bf4..3e8b87d 100644
  --- a/users-spec.yml
  +++ b/users-spec.yml
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
