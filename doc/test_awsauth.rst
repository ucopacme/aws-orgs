Functional Tests for awsauth tool
=================================

Prerequisites:

- admin access to auth account
- spec file setup

  - install template spec files
  - spec files under git
  - site specific paramaters defined in common.yaml
  - configure ~.awsorgs/config.yaml
  - create at least one satelite account (see awsaccounts)



Users and Groups - ``awsauth users``
------------------------------------

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
  - arn:aws:iam::962936672038:user/awsauth/sysadm/agould
  - arn:aws:iam::962936672038:user/awsauth/drivera
  - arn:aws:iam::962936672038:user/awsauth/jhsu
  
  Groups:
  - arn:aws:iam::962936672038:group/awsauth/all-users
  - arn:aws:iam::962936672038:group/awsauth/orgadmins
  
  ____________________
  Account:    blee-dev
  ____________________
  Account:    blee-poc
  _____________________
  Account:    blee-prod
  __________________
  Account:    master
  Users:
  - arn:aws:iam::640965621536:user/agould
  
  Groups:
  - arn:aws:iam::640965621536:group/Admins


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



Cross Account Access Delegations - ``awsauth delegations``
----------------------------------------------------------

Prerequisites:

- IAM group with users to use as ``TrustedGroup``


Commands used:

- git diff
- awsauth delegations
- awsauth delegations --exec
- awsauth report --roles


Spec files impacted:

- delegations-spec.yml
- custom-policy-spec.yml


Actions:

- create a cross account access delegation
- update the delegation definition
- update attached custom policy
- delete delegation


Create a cross account access delegation
****************************************

File to edit: delegations-spec.yml

- set ``TrustedGroup`` to your new group
- define a list of accounts in ``TrustingAccount``
- define one managed policy in ``Policies``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/delegations-spec.yml b/delegations-spec.yml
  index 1ae3245..4d571e9 100644
  --- a/delegations-spec.yml
  +++ b/delegations-spec.yml
  @@ -101,3 +101,14 @@ delegations:
   
  +  - RoleName: TestersRole
  +    Ensure: present
  +    Description: testing cross account delegation
  +    TrustingAccount:
  +    TrustedGroup: testers
  +    RequireMFA: True
  +    Policies:
  +      - ReadOnlyAccess


Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ awsauth report --roles  | egrep "^Account|role/awsauth"


Update the delegation
*********************

change ``TrustingAccount`` to keyword ``ALL``::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi delegations-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/delegations-spec.yml b/delegations-spec.yml
  index 282db35..e46ac9e 100644
  --- a/delegations-spec.yml
  +++ b/delegations-spec.yml
  @@ -104,14 +104,10 @@ delegations:
     - RoleName: TestersRole
       Ensure: present
       Description: testing cross account delegation
  -    TrustingAccount:
  -      - blee-dev
  -      - blee-poc
  -      - blee-prod
  +    TrustingAccount: ALL
       TrustedGroup: testers
       RequireMFA: True
       Policies:
         - ReadOnlyAccess
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations
  [dryrun] awsorgs.utils: INFO     Updating policy 'AllowAssumeRole-TestersRole' for group 'testers' in account 'Managment':
    Statement:
    - Action: sts:AssumeRole
      Effect: Allow
  -   Resource:
  -   - arn:aws:iam::219234291074:role/awsauth/TestersRole
  ?   ^              ^^^^^^^^^^^^
  +   Resource: arn:aws:iam::\*:role/awsauth/TestersRole
  ?   ^^^^^^^^^              ^
  -   - arn:aws:iam::403999741647:role/awsauth/TestersRole
  -   - arn:aws:iam::633495783471:role/awsauth/TestersRole
    Version: '2012-10-17'
  
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'gorp-poc'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'test2'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'master'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'Managment'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'gorp-dev'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'gorp-prod'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'Security'
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations --exec
  awsorgs.utils: WARNING  /home/ashely/.awsorgs/spec.d/.gitignore not a valid yaml file. skipping
  awsorgs.utils: WARNING  /home/ashely/.awsorgs/spec.d/.delegations-spec.yml.swp not a valid yaml file. skipping
  awsorgs.utils: INFO     Updating policy 'AllowAssumeRole-TestersRole' for group 'testers' in account 'Managment':
    Statement:
    - Action: sts:AssumeRole
      Effect: Allow
  -   Resource:
  -   - arn:aws:iam::219234291074:role/awsauth/TestersRole
  ?   ^              ^^^^^^^^^^^^
  +   Resource: arn:aws:iam::\*:role/awsauth/TestersRole
  ?   ^^^^^^^^^              ^
  -   - arn:aws:iam::403999741647:role/awsauth/TestersRole
  -   - arn:aws:iam::633495783471:role/awsauth/TestersRole
    Version: '2012-10-17'
  
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'Security'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'gorp-poc'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'gorp-dev'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'test2'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'gorp-prod'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'Managment'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'master'
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'test2':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'gorp-prod':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'gorp-poc':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'gorp-dev':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'Security':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'Managment':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'master':


define a list of accounts in ``ExcludeAccounts``
************************************************

::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi delegations-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/delegations-spec.yml b/delegations-spec.yml
  index e46ac9e..8b01bb8 100644
  --- a/delegations-spec.yml
  +++ b/delegations-spec.yml
  @@ -105,6 +105,10 @@ delegations:
       Ensure: present
       Description: testing cross account delegation
       TrustingAccount: ALL
  +    ExcludeAccounts: 
  +      - gorp-poc
  +      - gorp-dev
  +      - gorp-prod
       TrustedGroup: testers
       RequireMFA: True
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations
  [dryrun] awsorgs.utils: INFO     Creating assume role policy 'DenyAssumeRole-TestersRole' for group 'testers' in account 'Managment':
  Statement:
  - Action: sts:AssumeRole
    Effect: Deny
    Resource:
    - arn:aws:iam::215031690010:role/awsauth/TestersRole
    - arn:aws:iam::598608341536:role/awsauth/TestersRole
    - arn:aws:iam::534447840478:role/awsauth/TestersRole
  
  [dryrun] awsorgs.utils: INFO     Deleting role 'TestersRole' from account 'gorp-dev'
  [dryrun] awsorgs.utils: INFO     Deleting role 'TestersRole' from account 'gorp-prod'
  [dryrun] awsorgs.utils: INFO     Deleting role 'TestersRole' from account 'gorp-poc'
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations --exec
  awsorgs.utils: INFO     Creating assume role policy 'DenyAssumeRole-TestersRole' for group 'testers' in account 'Managment':
  Statement:
  - Action: sts:AssumeRole
    Effect: Deny
    Resource:
    - arn:aws:iam::215031690010:role/awsauth/TestersRole
    - arn:aws:iam::598608341536:role/awsauth/TestersRole
    - arn:aws:iam::534447840478:role/awsauth/TestersRole
  Version: '2012-10-17'
  awsorgs.utils: INFO     Deleting role 'TestersRole' from account 'gorp-poc'
  awsorgs.utils: INFO     Deleting role 'TestersRole' from account 'gorp-dev'
  awsorgs.utils: INFO     Deleting role 'TestersRole' from account 'gorp-prod'



attach a custom policy::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi custom-policy-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi delegations-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/custom-policy-spec.yml b/custom-policy-spec.yml
  index 9399a60..a428164 100644
  --- a/custom-policy-spec.yml
  +++ b/custom-policy-spec.yml
  @@ -120,3 +120,14 @@ custom_policies:
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
  diff --git a/delegations-spec.yml b/delegations-spec.yml
  index 8b01bb8..ce9afa9 100644
  --- a/delegations-spec.yml
  +++ b/delegations-spec.yml
  @@ -113,5 +113,6 @@ delegations:
       RequireMFA: True
       Policies:
         - ReadOnlyAccess
  +      - ReadS3Bucket
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations
  [dryrun] awsorgs.utils: WARNING  /home/ashely/.awsorgs/spec.d/.gitignore not a valid yaml file. skipping
  [dryrun] awsorgs.utils: INFO     Creating custom policy 'ReadS3Bucket' in account 'blee-dev':
  Statement:
  - Action:
    - s3:List*
    - s3:Get*
    Effect: Allow
    Resource:
    - arn:aws:s3:::my_bucket
    - arn:aws:s3:::my_bucket/*
  Version: '2012-10-17'
  
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'blee-dev'
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'Security'
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'Managment'
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'blee-prod'
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'master'
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'test2'
  [dryrun] awsorgs.utils: INFO     Creating custom policy 'ReadS3Bucket' in account 'blee-poc':
  Statement:
  - Action:
    - s3:List*
    - s3:Get*
    Effect: Allow
    Resource:
    - arn:aws:s3:::my_bucket
    - arn:aws:s3:::my_bucket/*
  Version: '2012-10-17'
  
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'blee-poc'
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations --exec
  awsorgs.utils: WARNING  /home/ashely/.awsorgs/spec.d/.gitignore not a valid yaml file. skipping
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'Security'
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'Managment'
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'master'
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'blee-prod'
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'test2'
  awsorgs.utils: INFO     Creating custom policy 'ReadS3Bucket' in account 'blee-dev':
  Statement:
  - Action:
    - s3:List*
    - s3:Get*
    Effect: Allow
    Resource:
    - arn:aws:s3:::my_bucket
    - arn:aws:s3:::my_bucket/*
  Version: '2012-10-17'
  
  awsorgs.utils: INFO     Creating custom policy 'ReadS3Bucket' in account 'blee-poc':
  Statement:
  - Action:
    - s3:List*
    - s3:Get*
    Effect: Allow
    Resource:
    - arn:aws:s3:::my_bucket
    - arn:aws:s3:::my_bucket/*
  Version: '2012-10-17'
  
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'blee-dev'
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to role 'TestersRole' in account 'blee-poc'





modify a custom policy::

(python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
diff --git a/custom-policy-spec.yml b/custom-policy-spec.yml
index a428164..7efe46b 100644
--- a/custom-policy-spec.yml
+++ b/custom-policy-spec.yml
@@ -131,3 +131,5 @@ custom_policies:
         Resource:
           - arn:aws:s3:::my_bucket
           - arn:aws:s3:::my_bucket/*
+          - arn:aws:s3:::my_other_bucket
+          - arn:aws:s3:::my_other_bucket/*






modify the ``Description``
delete the delegation

::
