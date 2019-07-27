Cross Account Access Delegations - ``awsauth delegations``
==========================================================

Prerequisites:

- IAM group with users to use as ``TrustedGroup``


Commands used:

- git diff
- awsauth delegations
- awsauth delegations --exec
- awsauth report --roles


Spec files impacted:

- delegations.yaml
- custom_policies.yaml
- policy_sets.yaml


Actions:

- `Create a cross account access delegation`_
- `Update the delegation to apply to all accounts`_
- `Exclude some accounts from a delegation`_
- `Attach a custom policy`_
- `Modify a custom policy`_
- `Create a policy set and apply it to the delegation`_
- `Delete the delegation from all accounts`_


Create a cross account access delegation
****************************************

File to edit: delegations.yaml

- set ``TrustedGroup`` to your new group
- define a list of accounts in ``TrustingAccount``
- define one managed policy in ``Policies``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/delegations.yaml b/delegations.yaml
  index 1ae3245..4d571e9 100644
  --- a/delegations.yaml
  +++ b/delegations.yaml
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
  $ awsauth report --roles  | egrep "^Account|TestersRole"
  $ aws iam list-group-policies --group-name testers


Update the delegation to apply to all accounts
**********************************************

File to edit: delegations.yaml

- set ``TrustingAccount`` to keyword ``ALL``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/delegations.yaml b/delegations.yaml
  index 282db35..e46ac9e 100644
  --- a/delegations.yaml
  +++ b/delegations.yaml
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

Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ awsauth report --roles  | egrep "^Account|TestersRole"
  $ aws iam list-group-policies --group-name testers
  $ aws iam get-group-policy --group-name testers --policy-name AllowAssumeRole-TestersRole


Exclude some accounts from a delegation
***************************************

File to edit: delegations.yaml

- define a list of accounts in ``ExcludeAccounts``

Example Diff::

  :~/.awsorgs/spec.d> git diff
  diff --git a/delegations.yaml b/delegations.yaml
  index e46ac9e..8b01bb8 100644
  --- a/delegations.yaml
  +++ b/delegations.yaml
  @@ -105,6 +105,10 @@ delegations:
       Ensure: present
       Description: testing cross account delegation
       TrustingAccount: ALL
  +    ExcludeAccounts: 
  +      - blee-dev
  +      - blee-prod
       TrustedGroup: testers
       RequireMFA: True


Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ awsauth report --roles  | egrep "^Account|TestersRole"
  $ aws iam list-group-policies --group-name testers
  $ aws iam get-group-policy --group-name testers --policy-name AllowAssumeRole-TestersRole
  $ aws iam get-group-policy --group-name testers --policy-name DenyAssumeRole-TestersRole


Attach a custom policy
**********************

Files to edit:

- custom_policies.yaml
- delegations.yaml

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/custom_policies.yaml b/custom_policies.yaml
  index 9399a60..a428164 100644
  --- a/custom_policies.yaml
  +++ b/custom_policies.yaml
  @@ -120,3 +120,14 @@ custom_policies:
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
  diff --git a/delegations.yaml b/delegations.yaml
  index 8b01bb8..ce9afa9 100644
  --- a/delegations.yaml
  +++ b/delegations.yaml
  @@ -113,5 +113,6 @@ delegations:
       RequireMFA: True
       Policies:
         - ReadOnlyAccess
  +      - ReadS3Bucket


Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ awsauth report --roles  | egrep "^Account|awsauth/ReadS3Bucket"
  $ aws iam list-group-policies --group-name testers
  $ aws iam get-group-policy --group-name testers --policy-name AllowAssumeRole-TestersRole
  $ aws iam get-group-policy --group-name testers --policy-name DenyAssumeRole-TestersRole


Modify a custom policy
**********************

Files to edit:

- custom_policies.yaml

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/custom_policies.yaml b/custom_policies.yaml
  index a428164..7efe46b 100644
  --- a/custom_policies.yaml
  +++ b/custom_policies.yaml
  @@ -131,3 +131,5 @@ custom_policies:
           Resource:
             - arn:aws:s3:::my_bucket
             - arn:aws:s3:::my_bucket/*
  +          - arn:aws:s3:::my_other_bucket
  +          - arn:aws:s3:::my_other_bucket/*

Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ awsauth report --roles --full | grep -A12 awsauth/ReadS3Bucket


Create a policy set and apply it to the delegation
**************************************************

Files to edit:

- policy_sets.yaml

  - create a new policy_set:
  
    -  use the same policies as are listed in the delegation
    -  include a tag and value of your choice

- delegations.yaml

  - delete the ``Policies`` attribute from the delegation
  - set the ``PolicySet`` attribute to the name of your new policy set

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/policy_sets.yaml b/policy_sets.yaml
  index ae4c72d..1d991d2 100644
  --- a/policy_sets.yaml
  +++ b/policy_sets.yaml
  @@ -18,6 +18,14 @@ policy_sets:

  +- Name: TesterPolicySet
  +  Description: Access for testers
  +  Tags:
  +  - Key: jobfunctionrole
  +    Value: True
  +  Policies:
  +  - ReadOnlyAccess
  +  - ReadS3Bucket

  diff --git a/delegations.yaml b/delegations.yaml
  index 1ae3245..4d571e9 100644
  --- a/delegations.yaml
  +++ b/delegations.yaml
  @@ -101,3 +101,14 @@ delegations:
   
     - RoleName: TestersRole
       Ensure: present
       Description: testing cross account delegation
       TrustingAccount:
       TrustedGroup: testers
       RequireMFA: True
  -    Policies:
  -      - ReadOnlyAccess
  -      - ReadS3Bucket
  +    PolicySet: TesterPolicySet
  +      - ReadOnlyAccess
  +      - ReadS3Bucket


Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ aws iam list-role-tags --role-name TestersRole


Delete the delegation from all accounts
***************************************

Files to edit: delegations.yaml

- set ``Ensure: absent``

Example Diff::

  ~/.awsorgs/spec.d> git diff
  diff --git a/delegations.yaml b/delegations.yaml
  index 2b050da..b6892d1 100644
  --- a/delegations.yaml
  +++ b/delegations.yaml
  @@ -67,14 +67,10 @@ delegations:
         - ViewBilling
   
     - RoleName: TestersRole
  -    Ensure: present
  +    Ensure: absent
       Description: testing cross account delegation
       TrustingAccount: ALL
       ExcludeAccounts: 
         - blee-poc
         - blee-dev
         - blee-prod

Review proposed changes in ``dry-run`` mode::

  $ awsauth delegations

Implement and review changes::  

  $ awsauth delegations --exec
  $ awsauth report --roles  | egrep "^Account|role/awsauth/ReadS3Bucket"
  $ aws iam list-group-policies --group-name testers


