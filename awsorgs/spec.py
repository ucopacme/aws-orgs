import sys
import os
import yaml

from awsorgs.utils import yamlfmt
from awsorgs.spec_validation_data import spec_patterns

# Spec parser defaults
DEFAULT_CONFIG_FILE = '~/.awsorgs/config.yaml'
DEFAULT_SPEC_DIR = '~/.awsorgs/spec.d'


def load_config(log, args):
    if args['--config']:
        config_file = args['--config']
    else:
        config_file = DEFAULT_CONFIG_FILE
    config_file = os.path.expanduser(config_file)
    log.debug("calling load_config() for file '%s'" % config_file)
    with open(config_file) as f:
        config = yaml.load(f.read())
    log.debug("loading config file into spec: {}".format(yamlfmt(config))) 
    return config


def validate_spec_file(log, spec_file, validation_patterns):
    """
    Validate spec-file is properly formed.
    """
    with open(spec_file) as f:
        try:
            spec = yaml.load(f.read())
        except yaml.scanner.ScannerError:
            log.warn("{} not a valid yaml file. skipping".format(spec_file))
            return
    log.debug("calling validate_spec() for file '%s'" % spec_file)
    for key, value in spec.items():
        if not validate_spec(log, validation_patterns, key, value):
            log.error("Spec file '%s' failed syntax validation on key '%s'" % (
                    spec_file, key))
    return spec


#def validate_spec_file(log, spec_file, pattern_name):
#    """
#    Validate spec-file is properly formed.
#    """
#    with open(spec_file) as f:
#        spec = yaml.load(f.read())
#    log.debug("calling validate_spec() for pattern '%s'" % pattern_name)
#    if validate_spec(log, validation_patterns, pattern_name, spec):
#        return spec
#    else:
#        log.critical("Spec file '%s' failed syntax validation" % spec_file)
#        sys.exit(1)


def validate_spec(log, validation_patterns, pattern_name, spec):
    """
    Validate syntax of a given 'spec' dictionary against the
    named spec_pattern.
    """
    pattern = validation_patterns[pattern_name]
    valid_spec = True
    # test for required attributes
    required_attributes = [attr for attr in pattern if pattern[attr]['required']]
    for attr in required_attributes:
        if attr not in spec:
            log.error("Required attribute '%s' not found in '%s' spec. Context: %s" %
                    (attr, pattern_name, spec))
            valid_spec = False
    for attr in spec:
        log.debug("  considering attribute '%s'" % attr)
        # test if attribute is permitted
        if attr not in pattern:
            log.warn("Attribute '%s' does not exist in validation pattern '%s'" %
                    (attr, pattern_name))
            continue
        # handle recursive patterns
        if 'spec_pattern' in pattern[attr]:
            pattern_name = pattern[attr]['spec_pattern']
            if not isinstance(spec[attr], list):
                log.error("Attribute '%s' must be a list of '%s' specs.  Context: %s" %
                        (attr, pattern_name, spec))
                valid_spec = False
                continue
            for sub_spec in spec[attr]:
                log.debug("calling validate_spec() for pattern '%s'" % pattern_name)
                log.debug("context: %s" % sub_spec)
                if not validate_spec(log, validation_patterns, pattern_name, sub_spec):
                    valid_spec = False
        # test attribute type. ignore attr if value is None
        elif spec[attr]:
            spec_attr_type = spec[attr].__class__.__name__
            log.debug("    spec attribute object type: '%s'" % (spec_attr_type))
            # simple attribute pattern
            if isinstance(pattern[attr]['atype'], str):
                if spec_attr_type != pattern[attr]['atype']:
                    log.error("Attribute '%s' must be of type '%s'" %
                            (attr, pattern[attr]['atype']))
                    valid_spec = False
                    continue
            else:
                # complex attribute pattern
                valid_types = list(pattern[attr]['atype'].keys())
                log.debug("    pattern attribute types: '%s'" % valid_types)
                if not spec_attr_type in valid_types: 
                    log.error("Attribute '%s' must be one of type '%s'" %
                            (attr, valid_types))
                    valid_spec = False
                    continue
                atype = pattern[attr]['atype'][spec_attr_type]
                # test attributes values
                if atype and 'values' in atype:
                    log.debug("    allowed values for attribute '%s': %s" %
                            (attr, atype['values']))
                    if not spec[attr] in atype['values']:
                        log.error("Value of attribute '%s' must be one of '%s'" %
                                (attr, atype['values']))
                        valid_spec = False
                        continue
    return valid_spec


def load_spec_files(log, args, config):
    spec_dir = config.get('spec_dir', args.get('--spec-dir'))
    if not spec_dir:
        spec_dir = DEFAULT_SPEC_DIR
    spec_dir = os.path.expanduser(spec_dir)
    log.debug("calling load_spec_files() for spec_dir '%s'" % spec_dir)
    validation_patterns = yaml.load(spec_patterns)
    #log.debug("loading spec validation patterns: {}".format(yamlfmt(validation_patterns)))
    spec = dict()
    for root, _, filenames in os.walk(spec_dir):
        for f in filenames:
            log.debug("considering file {}".format(f))
            new_spec = validate_spec_file(log, 
                    os.path.join(spec_dir, f), validation_patterns)
            if new_spec:
                spec.update(new_spec)
    return spec
