"""
Spec validator schema data

ISSUES:
    place regex rule on email addresses, domain name
"""
import yaml

from cerberus import Validator, schema_registry
from awsorgs.utils import yamlfmt


# Schema for validating spec files.  Since spec is accumulated from multiple
# files, we do not place a 'require' rule on first level keys.  Individual spec
# files have only a subset of these.
#
SPEC_FILE_SCHEMA = """
master_account_id:
  type: string
auth_account_id:
  type: string
default_domain:
  type: string
default_sc_policy:
  type: string
default_ou:
  type: string
default_path:
  type: string
default_smtp_server:
  type: string
org_admin_team:
  type: string
organizational_units:
  required: False
  type: list
  schema:
    type: dict
    schema: organizational_unit
sc_policies:
  required: False
  type: list
  schema:
    type: dict
    schema: sc_policy
teams:
  required: False
  type: list
  schema:
    type: dict
    schema: team
accounts:
  required: False
  type: list
  schema:
    type: dict
    schema: account
users:
  required: False
  type: list
  schema:
    type: dict
    schema: user
groups:
  required: False
  type: list
  schema:
    type: dict
    schema: group
delegations:
  required: False
  type: list
  schema:
    type: dict
    schema: delegation
local_users:
  required: False
  type: list
  schema:
    type: dict
    schema: local_user
custom_policies:
  required: False
  type: list
  schema:
    type: dict
    schema: custom_policy
"""


# Schema for validating the fully accumulate spec object.  This is where we
# ensure all required keys are present.  But we do not need to check sub
# schema, as that is done during spec_file validation.
#
SPEC_SCHEMA = """
master_account_id:
  required: True
  type: string
auth_account_id:
  required: True
  type: string
default_domain:
  required: True
  type: string
default_sc_policy:
  required: True
  type: string
default_ou:
  required: True
  type: string
default_path:
  required: True
  type: string
default_smtp_server:
  required: True
  type: string
org_admin_team:
  required: True
  type: string
organizational_units:
  required: True
  type: list
sc_policies:
  required: True
  type: list
teams:
  required: True
  type: list
accounts:
  required: True
  type: list
users:
  required: True
  type: list
groups:
  required: True
  type: list
delegations:
  required: True
  type: list
local_users:
  required: True
  type: list
custom_policies:
  required: True
  type: list
"""


ORGANIZATIONAL_UNIT_SCHEMA = """
Name:
  required: True
  type: string
Accounts:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Child_OU:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: organizational_unit
SC_Policies:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

SC_POLICY_SCHEMA = """
Name:
  required: True
  type: string
Description:
  required: False
  type: string
Effect:
  required: False
  type: string
  allowed:
  - Allow
  - Deny
Actions:
  required: False
  type: list
  schema:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

TEAM_SCHEMA = """
Name:
  required: True
  type: string
Description:
  required: True
  type: string
BusinessContacts:
  required: True
  type: list
  schema:
    type: string
TechnicalContacts:
  required: True
  type: list
  schema:
    type: string
"""

ACCOUNT_SCHEMA = """
Name:
  required: True
  type: string
Email:
  required: False
  type: string
Team:
  required: True
  type: string
Alias:
  required: False
  type: string
"""

USER_SCHEMA = """
Name:
  required: True
  type: string
Team:
  required: True
  type: string
Email:
  required: True
  type: string
Path:
  required: False
  type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

GROUP_SCHEMA = """
Name:
  required: True
  type: string
Path:
  required: False
  type: string
Members:
  required: False
  nullable: True
  anyof:
  - type: string
    allowed:  
    - ALL
  - type: list
    schema:
      type: string
ExcludeMembers:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Policies:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

LOCAL_USER_SCHEMA = """
Name:
  required: True
  type: string
Description:
  required: False
  type: string
Team:
  required: True
  type: string
Path:
  required: False
  type: string
#AuthMethod:
#  required: False
#  type: string
Account:
  required: True
  anyof:
  - type: string
    allowed:  
    - ALL
  - type: list
    schema:
      type: string
ExcludeAccounts:
  required: False
  type: list
  schema:
    type: string
#TrustedGroup:
#  required: False
#  type: string
Policies:
  required: False
  type: list
  schema:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

DELEGATION_SCHEMA = """
RoleName:
  required: True
  type: string
Description:
  required: False
  type: string
TrustingAccount:
  required: True
  anyof:
  - type: string
    allowed:  
    - ALL
  - type: list
    schema:
      type: string
ExcludeAccounts:
  required: False
  type: list
  schema:
    type: string
TrustedGroup:
  required: False
  type: string
TrustedAccount:
  required: False
  type: string
RequireMFA:
  required: False
  type: boolean
Policies:
  required: False
  type: list
  schema:
    type: string
Path:
  required: False
  type: string
Duration:
  required: False
  type: integer
  min: 3600
  max: 43200
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

CUSTOM_POLICY_SCHEMA = """
PolicyName:
  required: True
  type: string
Description:
  required: False
  type: string
Statement:
  required: True
  anyof:
  - type: string
  - type: list
    schema:
      type: dict
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""


def file_validator(log):
    schema_registry.add('organizational_unit', yaml.load(ORGANIZATIONAL_UNIT_SCHEMA))
    schema_registry.add('sc_policy', yaml.load(SC_POLICY_SCHEMA))
    schema_registry.add('team', yaml.load(TEAM_SCHEMA))
    schema_registry.add('account', yaml.load(ACCOUNT_SCHEMA))
    schema_registry.add('user', yaml.load(USER_SCHEMA))
    schema_registry.add('group', yaml.load(GROUP_SCHEMA))
    schema_registry.add('local_user', yaml.load(LOCAL_USER_SCHEMA))
    schema_registry.add('delegation', yaml.load(DELEGATION_SCHEMA))
    schema_registry.add('custom_policy', yaml.load(CUSTOM_POLICY_SCHEMA))
    log.debug("adding subschema to schema_registry: {}".format(
            schema_registry.all().keys()))
    vfile = Validator(yaml.load(SPEC_FILE_SCHEMA))
    log.debug("file_validator_schema: {}".format(vfile.schema))
    return vfile


def spec_validator(log):
    vspec = Validator(yaml.load(SPEC_SCHEMA))
    log.debug("spec_validator_schema: {}".format(vspec.schema))
    return vspec
