import sys
import os
import yaml

from cerberus import Validator, schema_registry

from awsorgs.utils import yamlfmt
from awsorgs.spec_validation_data import spec_patterns

# Spec parser defaults
DEFAULT_CONFIG_FILE = '~/.awsorgs/config.yaml'
DEFAULT_SPEC_DIR = '~/.awsorgs/spec.d'



organizational_unit = """
  Name:
    required: True
    atype: str
  Accounts:
    required: False
    atype: list
  Child_OU:
    required: False
    spec_pattern: organizational_unit
    atype: list
  SC_Policies:
    required: False
    atype: list
  Ensure:
    required: False
    atype:
      str:
        values:
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
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""


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
org_access_role:
  type: string
default_path:
  type: string
organizational_units:
  required: False
  type: list
sc_policies:
  required: False
  type: list
  schema:
    type: dict
    schema: sc_policy

teams:
  required: False
  type: list
accounts:
  required: False
  type: list
users:
  required: False
  type: list
groups:
  required: False
  type: list
delegations:
  required: False
  type: list
local_users:
  required: False
  type: list
custom_policies:
  required: False
  type: list
"""

SPEC_SCHEMA = """
master_account_id:
  type: string
  required: True
auth_account_id:
  type: string
default_domain:
  type: string
default_sc_policy:
  type: string
default_ou:
  type: string
org_access_role:
  type: string
default_path:
  type: string
organizational_units:
  required: False
  type: list
sc_policies:
  required: False
  type: list
teams:
  required: False
  type: list
accounts:
  required: False
  type: list
users:
  required: False
  type: list
groups:
  required: False
  type: list
delegations:
  required: False
  type: list
local_users:
  required: False
  type: list
custom_policies:
  required: False
  type: list
"""


def load_config(log, args):
    if args['--config']:
        config_file = args['--config']
    else:
        config_file = DEFAULT_CONFIG_FILE
    config_file = os.path.expanduser(config_file)
    log.debug("calling load_config() for file '%s'" % config_file)
    with open(config_file) as f:
        config = yaml.load(f.read())
    log.debug("loading config file:\n{}".format(yamlfmt(config))) 
    return config


def validate_spec_file(log, spec_file, validator):
    """
    Validate spec-file is properly formed.
    """
    with open(spec_file) as f:
        try:
            spec_from_file = yaml.load(f.read())
        except yaml.scanner.ScannerError:
            log.warn("{} not a valid yaml file. skipping".format(spec_file))
            return
    if validator.validate(spec_from_file):
        log.debug("validation passed")
        return spec_from_file
    else:
        log.error(validator.errors)
        return None
    return spec_from_file


def load_spec_files(log, args, config):
    spec_dir = config.get('spec_dir', args.get('--spec-dir'))
    if not spec_dir:
        spec_dir = DEFAULT_SPEC_DIR
    spec_dir = os.path.expanduser(spec_dir)
    log.debug("calling load_spec_files() for spec_dir '%s'" % spec_dir)
    schema = yaml.load(SPEC_FILE_SCHEMA)
    log.debug("schema: {}".format(schema))
    validator = Validator(yaml.load(SPEC_FILE_SCHEMA))
    spec = {}
    for root, _, filenames in os.walk(spec_dir):
        for f in filenames:
            log.debug("considering file {}".format(f))
            spec_from_file = validate_spec_file(log, os.path.join(spec_dir, f), validator)
            if spec_from_file:
                spec.update(spec_from_file)
    log.debug("spec:\n{}".format(yamlfmt(spec)))
    return spec


def validate_spec(log, args, config):
    schema_registry.add('sc_policy', yaml.load(SC_POLICY_SCHEMA))
    log.debug("adding sc_policy schema to schema_registry: {}".format(schema_registry.get('sc_policy')))
    spec = load_spec_files(log, args, config)
    #validator = Validator(yaml.load(SPEC_SCHEMA))

