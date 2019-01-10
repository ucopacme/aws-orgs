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



Users and Groups
----------------

Commands used:

- git diff
- awsauth users
- awsauth users --exec


Spec files impacted:

- users-spec.yml
- groups-spec.yml
- custom-policy-spec.yml


Actions:

- create an IAM user and group, and add the user to the group
- attach a IAM managed policy to your group
- attach a IAM custom policy to your group
- modify attached custom policy
- detach policies, users from group
- delete group, delete user


Part 1 - AIM User and Group in Auth Account
*******************************************

create an IAM user and group, and add the user to the group::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi users-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi groups-spec.yml 

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index 7f37144..d3fe879 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
  @@ -46,3 +46,8 @@ groups:
         - ashely
         - quincey
         - egburt
  +  - Name: testers
  +    Ensure: present
  +    Members:
  +      - joeuser
  +
  diff --git a/users-spec.yml b/users-spec.yml
  index 22d2d61..5424bf4 100644
  --- a/users-spec.yml
  +++ b/users-spec.yml
  @@ -36,3 +36,6 @@ users:
     - Name: drivera
       Email: david.rivera@ucop.edu
       Team: syseng
  +  - Name: joeuser
  +    Email: joeuser@example.com
  +    Team: test

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users
  [dryrun] awsorgs.utils: INFO     Creating user 'joeuser'
  [dryrun] awsorgs.utils: INFO     Creating group 'testers'
  [dryrun] awsorgs.utils: INFO     Adding user 'joeuser' to group 'all-users'

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users --exec
  awsorgs.utils: INFO     Creating user 'joeuser'
  awsorgs.utils: INFO     arn:aws:iam::962936672038:user/awsauth/joeuser
  awsorgs.utils: INFO     Creating group 'testers'
  awsorgs.utils: INFO     arn:aws:iam::962936672038:group/awsauth/testers
  awsorgs.utils: INFO     Adding user 'joeuser' to group 'all-users'
  awsorgs.utils: INFO     Adding user 'joeuser' to group 'testers'



Part II - IAM Group Policies in Auth Account
********************************************

attach a IAM managed policy to your group::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi groups-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index d3fe879..9e05738 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
  @@ -50,4 +50,6 @@ groups:
     - Name: testers
       Ensure: present
       Members:
         - joeuser
  +    Policies:
  +      - IAMReadOnlyAccess
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users
  [dryrun] awsorgs.utils: INFO     Attaching policy 'IAMReadOnlyAccess' to group 'testers' in account 'Managment'

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users --exec
  awsorgs.utils: INFO     Attaching policy 'IAMReadOnlyAccess' to group 'testers' in account 'Managment'


attach a IAM custom policy to your group::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi custom-policies-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi groups-spec.yml 

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/custom-policy-spec.yml b/custom-policy-spec.yml
  index 9399a60..d6f29d7 100644
  --- a/custom-policy-spec.yml
  +++ b/custom-policy-spec.yml
  @@ -120,3 +120,19 @@ custom_policies:
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
  +      - Effect: Allow
  +        Action:
  +          - s3:ListAllMyBuckets
  +          - s3:GetBucketLocation
  +        Resource: '*'
  diff --git a/groups-spec.yml b/groups-spec.yml
  index d3fe879..9e05738 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
  @@ -50,4 +50,6 @@ groups:
     - Name: testers
       Ensure: present
       Members:
         - joeuser
  +    Policies:
  +      - IAMReadOnlyAccess
  +      - ReadS3Bucket
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users
  [dryrun] awsorgs.utils: INFO     Creating custom policy 'ReadS3Bucket' in account 'Managment':
  Statement:
  - Action:
    - s3:List*
    - s3:Get*
    Effect: Allow
    Resource:
    - arn:aws:s3:::my_bucket
    - arn:aws:s3:::my_bucket/*
  - Action:
    - s3:ListAllMyBuckets
    - s3:GetBucketLocation
    Effect: Allow
    Resource: '*'
  Version: '2012-10-17'
  [dryrun] awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to group 'testers' in account 'Managment'
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users --exec
  awsorgs.utils: INFO     Creating custom policy 'ReadS3Bucket' in account 'Managment':
  Statement:
  - Action:
    - s3:List*
    - s3:Get*
    Effect: Allow
    Resource:
    - arn:aws:s3:::my_bucket
    - arn:aws:s3:::my_bucket/*
  - Action:
    - s3:ListAllMyBuckets
    - s3:GetBucketLocation
    Effect: Allow
    Resource: '*'
  Version: '2012-10-17'
  awsorgs.utils: INFO     Attaching policy 'ReadS3Bucket' to group 'testers' in account 'Managment'


modify attached custom policy::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi custom-policy-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
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
         - Effect: Allow
           Action:
             - s3:ListAllMyBuckets

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users
  [dryrun] awsorgs.utils: INFO     Updating custom policy 'ReadS3Bucket' in account 'Managment':
    Statement:
    - Action:
      - s3:List*
      - s3:Get*
      Effect: Allow
      Resource:
      - arn:aws:s3:::my_bucket
      - arn:aws:s3:::my_bucket/*
  +   - arn:aws:s3:::my_other_bucket
  +   - arn:aws:s3:::my_other_bucket/*
    - Action:
      - s3:ListAllMyBuckets
      - s3:GetBucketLocation
      Effect: Allow
      Resource: '*'
    Version: '2012-10-17'
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users --exec
  awsorgs.utils: INFO     Updating custom policy 'ReadS3Bucket' in account 'Managment':
    Statement:
    - Action:
      - s3:List*
      - s3:Get*
      Effect: Allow
      Resource:
      - arn:aws:s3:::my_bucket
      - arn:aws:s3:::my_bucket/*
  +   - arn:aws:s3:::my_other_bucket
  +   - arn:aws:s3:::my_other_bucket/*
    - Action:
      - s3:ListAllMyBuckets
      - s3:GetBucketLocation
      Effect: Allow
      Resource: '*'
    Version: '2012-10-17'


Part III - Clean Up
*******************

detach policies, users from group::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi groups-spec.yml 
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
       Policies:
  -      - IAMReadOnlyAccess
  -      - ReadS3Bucket

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users
  [dryrun] awsorgs.utils: INFO     Removing user 'joeuser' from group 'testers'
  [dryrun] awsorgs.utils: INFO     Detaching policy 'ReadS3Bucket' from group 'testers' in account 'Managment'
  [dryrun] awsorgs.utils: INFO     Detaching policy 'IAMReadOnlyAccess' from group 'testers' in account 'Managment'

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users --exec
  awsorgs.utils: INFO     Removing user 'joeuser' from group 'testers'
  awsorgs.utils: INFO     Detaching policy 'ReadS3Bucket' from group 'testers' in account 'Managment'
  awsorgs.utils: INFO     Detaching policy 'IAMReadOnlyAccess' from group 'testers' in account 'Managment'


delete group, delete user::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi groups-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi users-spec.yml 

  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/groups-spec.yml b/groups-spec.yml
  index 9e05738..4eda72b 100644
  --- a/groups-spec.yml
  +++ b/groups-spec.yml
  @@ -47,9 +47,6 @@ groups:
         - quincey
         - egburt
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
       Email: david.rivera@ucop.edu
       Team: syseng
     - Name: joeuser
  +    Ensure: absent
       Email: joeuser@example.com
       Team: test

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users
  [dryrun] awsorgs.utils: INFO     Deleting user 'joeuser'
  [dryrun] awsorgs.utils: INFO     Deleting group 'testers'
  [dryrun] awsorgs.utils: INFO     Removing user 'joeuser' from group 'all-users'

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth users --exec
  awsorgs.utils: INFO     Deleting user 'joeuser'
  awsorgs.utils: INFO     Deleting group 'testers'
  awsorgs.utils: INFO     Removing user 'joeuser' from group 'all-users'





Cross Account Access Delegations
--------------------------------

Prerequisites:

- create trusted group with users


Commands used:

- git diff
- awsauth users
- awsauth users --exec


Spec files impacted:

- users-spec.yml
- groups-spec.yml
- delegations-spec.yml
- custom-policy-spec.yml


Actions:

- create a cross account access delegation
- update the delegation definition
- update attached custom policy
- delete delegation


Create a cross account access delegation
****************************************

in delegations-spec.yml:

- set ``TrustedGroup`` to your new group
- define a list of accounts in ``TrustingAccount``
- define one managed policy in ``Policies``

::

  (python3.6) ashely@horus:~/.awsorgs/spec.d> vi delegations-spec.yml 
  (python3.6) ashely@horus:~/.awsorgs/spec.d> git diff
  diff --git a/delegations-spec.yml b/delegations-spec.yml
  index 1ae3245..4d571e9 100644
  --- a/delegations-spec.yml
  +++ b/delegations-spec.yml
  @@ -101,3 +101,14 @@ delegations:
       Policies:
         - ElasticLoadBalancingReadOnly
   
  +  - RoleName: TestersRole
  +    Ensure: present
  +    Description: testing cross account delegation
  +    TrustingAccount:
  +    TrustedGroup: testers
  +    RequireMFA: True
  +    Policies:
  +      - ReadOnlyAccess

  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations
  [dryrun] awsorgs.utils: INFO     Creating assume role policy 'AllowAssumeRole-TestersRole' for group 'testers' in account 'Managment':
  Statement:
  - Action: sts:AssumeRole
    Effect: Allow
    Resource:
    - arn:aws:iam::219234291074:role/awsauth/TestersRole
    - arn:aws:iam::403999741647:role/awsauth/TestersRole
    - arn:aws:iam::633495783471:role/awsauth/TestersRole
  Version: '2012-10-17'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'blee-dev'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'blee-poc'
  [dryrun] awsorgs.utils: INFO     Creating role 'TestersRole' in account 'blee-prod'
  
  (python3.6) ashely@horus:~/.awsorgs/spec.d> awsauth delegations --exec
  awsorgs.utils: INFO     Creating assume role policy 'AllowAssumeRole-TestersRole' for group 'testers' in account 'Managment':
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'blee-prod'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'blee-dev'
  awsorgs.utils: INFO     Creating role 'TestersRole' in account 'blee-poc'
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'blee-prod':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'blee-dev':
  awsorgs.utils: INFO     Attaching policy 'ReadOnlyAccess' to role 'TestersRole' in account 'blee-poc':


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


define a list of accounts in ``ExcludeAccounts``::

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



attach a custom policy
modify a custom policy
modify the ``Description``
delete the delegation

::
