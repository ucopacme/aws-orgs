import sys
import os
import yaml
from cerberus import Validator, schema_registry
from awsorgs.utils import yamlfmt
from awsorgs.validator import file_validator, spec_validator

# Spec parser defaults
DEFAULT_CONFIG_FILE = '~/.awsorgs/config.yaml'
DEFAULT_SPEC_DIR = '~/.awsorgs/spec.d'



def load_config(log, args):
    if args['--config']:
        config_file = args['--config']
    else:
        config_file = DEFAULT_CONFIG_FILE
    config_file = os.path.expanduser(config_file)
    log.debug("loading config file: {}".format(config_file))
    with open(config_file) as f:
        config = yaml.load(f.read())
    log.debug("config: {}".format(config))
    return config


def get_spec_dir(log, args, config):
    spec_dir = config.get('spec_dir', args.get('--spec-dir'))
    if not spec_dir:
        spec_dir = DEFAULT_SPEC_DIR
    spec_dir = os.path.expanduser(spec_dir)
    log.debug("spec_dir: %s" % spec_dir)
    # ISSUE: test dir exists
    return spec_dir


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


def validate_spec(log, args, config):
    """
    Load all spec files in spec_dir and validate against spec schema
    """

    # validate spec_files
    spec_dir = get_spec_dir(log, args, config)
    validator = file_validator(log)
    spec_object = {}
    errors = 0
    for root, _, filenames in os.walk(spec_dir):
        for f in filenames:
            log.debug("considering file {}".format(f))
            spec_from_file, errors = validate_spec_file(log,
                    os.path.join(spec_dir, f), validator, errors)
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

