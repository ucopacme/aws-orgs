Functional Tests for awsauth tool
=================================


Users and Groups
----------------

Prerequisites:

- spec file setup

  - install template spec files
  - put spec files under git
  - define site specific paramaters in common.yaml
  - configure your ~.awsorgs/config.yaml
  - configure auth account
  - create at least one satelite account (see awsaccounts)

- admin access to auth account

Part 1 - AIM User and Group in Auth Account
*******************************************

Commands:

- vi users-spec.yml
- vi groups-spec.yml
- git diff
- awsauth users
- awsauth users --exec

Actions:

- create an IAM user and group, and add the user to the group::

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

Commands:

- vi groups-spec.yml
- vi custom-policy-spec.yml
- git diff
- awsauth users
- awsauth users --exec

Actions:

- attach a IAM managed policy to your group::

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


- attach a IAM custom policy to your group::

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


- modify attached custom policy::

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

- detach policies, users from group::

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

- delete group, delete user::

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


awsauth delegations
*******************

- create user
- create group
- add user to group
- create delegation definition
  - set ``TrustedGroup`` to your new group
  - define a list of accounts in ``TrustingAccount``
  - define one managed policy in ``Policies``

- update delegation definition
  - change ``TrustingAccount`` to keyword ``ALL``
  - define a list of accounts in ``ExcludeAccounts``
