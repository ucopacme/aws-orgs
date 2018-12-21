import sys
import os
import yaml

import boto3
from botocore.exceptions import ClientError
from cerberus import Validator, schema_registry

from awsorgs.utils import *
from awsorgs.validator import file_validator, spec_validator

# Spec parser defaults
DEFAULT_CONFIG_FILE = '~/.awsorgs/config.yaml'
DEFAULT_SPEC_DIR = '~/.awsorgs/spec.d'



def scan_config_file(log, args):
    if args['--config']:
        config_file = args['--config']
    else:
        config_file = DEFAULT_CONFIG_FILE
    config_file = os.path.expanduser(config_file)
    if not os.path.isfile(config_file):
        log.error("config_file not found: {}".format(config_file))
        return None
    log.debug("loading config file: {}".format(config_file))
    with open(config_file) as f:
        try:
            config = yaml.load(f.read())
        except (yaml.scanner.ScannerError, UnicodeDecodeError):
            log.error("{} not a valid yaml file".format(config_file))
            return None
        except Exception as e:
            log.error("cant load config_file '{}': {}".format(config_file, e))
            return None
    log.debug("config: {}".format(config))
    return config


def get_master_account_id(log, args, config):
    """
    Determine the Org Master account id.  Try in order:
    cli option, config file, client.describe_organization()
    """
    if args['--master-account-id']:
        master_account_id = args['--master-account-id']
    else:
        master_account_id = config.get('master_account_id')
    if master_account_id:
        if not valid_account_id(log, master_account_id):
            log.critical("config option 'master_account_id' is not valid account Id")
            sys.exit(1)
    else:
        log.debug("'master_account_id' not set in config_file or as cli option")
        try:
            master_account_id = boto3.client('organizations'
                    ).describe_organization()['Organization']['MasterAccountId']
        except ClientError as e:
            log.critical("can not determine master_account_id: {}".format(e))
            sys.exit(1)
    log.debug("master_account_id: %s" % master_account_id)
    return master_account_id


def get_spec_dir(log, args, config):
    """
    Determine the spec directory.  Try in order:
    cli option, config file, DEFAULT_SPEC_DIR.
    """
    if '--spec-dir' in args and args['--spec-dir']:
        spec_dir = args['--spec-dir']
    elif config['spec_dir']:
        spec_dir = config['spec_dir']
    else:
        spec_dir = DEFAULT_SPEC_DIR
    spec_dir = os.path.expanduser(spec_dir)
    log.debug("spec_dir: %s" % spec_dir)
    return spec_dir


def load_config(log, args):
    """
    Assemble config options from various sources: cli options, config_file 
    params, defaults, etc., and merge them into 'args' dict.
    When we are done we should have found all of the following:

    master_account_id
    org_access_role
    spec_dir (except when handling reports)
    auth_account_id (except when called by awsorgs)
    """
    config = scan_config_file(log, args)
    args['--master-account-id'] = get_master_account_id(log, args, config)
    args['--spec-dir'] = get_spec_dir(log, args, config)
    if not args['--org-access-role']:
        args['--org-access-role'] =  config.get('org_access_role')
    if not args['--auth-account-id']:
        args['--auth-account-id'] =  config.get('auth_account_id')
    return args


def validate_spec_file(log, spec_file, validator, errors):
    with open(spec_file) as f:
        try:
            spec_from_file = yaml.load(f.read())
        except (yaml.scanner.ScannerError, UnicodeDecodeError):
            log.warn("{} not a valid yaml file. skipping".format(spec_file))
            return (None, errors)
        except Exception as e:
            log.error("cant load spec_file '{}': {}".format(spec_file, e))
            return (None, errors)
    if validator.validate(spec_from_file):
        return (spec_from_file, errors)
    else:
        log.error("schema validation failed for spec_file: {}".format(spec_file))
        log.debug("validator errors:\n{}".format(yamlfmt(validator.errors)))
        errors += 1
        return (None, errors)


def validate_spec(log, args):
    """
    Load all spec files in spec_dir and validate against spec schema
    """

    # validate spec_files
    spec_dir = args['--spec-dir']
    if not os.path.isdir(spec_dir):
        log.error("spec_dir not found or not a directory: {}".format(spec_dir))
        sys.exit(1)
    validator = file_validator(log)
    spec_object = {}
    errors = 0
    for dirpath, dirnames, filenames in os.walk(spec_dir, topdown = True):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for f in filenames:
            log.debug("considering file {}".format(f))
            spec_from_file, errors = validate_spec_file(log,
                    os.path.join(dirpath, f), validator, errors)
            if spec_from_file:
                spec_object.update(spec_from_file)
    if errors:
        log.critical("schema validation failed for {} spec files. run in debug mode for details".format(errors))
        sys.exit(1)
    log.debug("spec_object:\n{}".format(yamlfmt(spec_object)))

    # validate aggregated spec_object
    validator = spec_validator(log)
    if validator.validate(spec_object):
        log.debug("spec_object validation succeeded")
        return spec_object
    else:
        log.critical("spec_object validation failed:\n{}".format(
                yamlfmt(validator.errors)))
        sys.exit(1)

