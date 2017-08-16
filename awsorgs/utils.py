"""Utility functions used by the various awsorgs modules"""

import os
import pkg_resources
import re

import boto3
import yaml
import logging

def lookup(dlist, lkey, lvalue, rkey=None):
    """
    Use a known key:value pair to lookup a dictionary in a list of
    dictionaries.  Return the dictonary or None.  If rkey is provided,
    return the value referenced by rkey or None.  If more than one
    dict matches, raise an error.
    args:
        dlist:   lookup table -  a list of dictionaries
        lkey:    name of key to use as lookup criteria
        lvalue:  value to use as lookup criteria
        key:     (optional) name of key referencing a value to return
    """
    items = [d for d in dlist
             if lkey in d
             and d[lkey] == lvalue]
    if not items:
        return None
    if len(items) > 1:
        raise RuntimeError(
            "Data Error: lkey:lvalue lookup matches multiple items in dlist"
        )
    if rkey:
        if rkey in items[0]:
            return items[0][rkey]
        return None
    return items[0]


def ensure_absent(spec):
    """
    test if an 'Ensure' key is set to absent in dictionary 'spec'
    """
    if 'Ensure' in spec and spec['Ensure'] == 'absent': return True
    return False


def get_logger(args):
    """
    Setup logging.basicConfig from args.
    Return logging.Logger object.
    """
    log_level = logging.CRITICAL
    if args['--verbose'] or args['report'] or args['--boto-log']:
        log_level = logging.INFO
    if args['--debug']:
        log_level = logging.DEBUG
    if args['report']:
        log_format = '%(message)s'
    elif args['--exec']:
        log_format = '%(name)s: %(levelname)-8s%(message)s'
    else:
        log_format = '%(name)s: %(levelname)-8s[dryrun] %(message)s'
    if not args['--boto-log']:
        logging.getLogger('botocore').propagate = False
        logging.getLogger('boto3').propagate = False
    logging.basicConfig(format=log_format, level=log_level)
    log = logging.getLogger(__name__)
    return log


def get_root_id(org_client):
    """
    Query deployed AWS Organization for its Root ID.
    """
    roots = org_client.list_roots()['Roots']
    if len(roots) >1:
        raise RuntimeError("org_client.list_roots returned multiple roots.")
    return roots[0]['Id']


def validate_master_id(org_client, spec):
    """
    Don't mangle the wrong org by accident
    """
    master_account_id = org_client.describe_organization(
      )['Organization']['MasterAccountId']
    if master_account_id != spec['master_account_id']:
        errmsg = ("""The Organization Master Account Id '%s' does not
          match the 'master_account_id' set in the spec-file.  
          Is your '--profile' arg correct?""" % master_account_id)
        raise RuntimeError(errmsg)
    return


def load_spec_patterns():
    """
    Return dict of patterns for use when validating specification syntax
    """
    filename =  os.path.abspath(pkg_resources.resource_filename(
            __name__, '../data/specification-formats.yaml'))
    with open(filename) as f:
        return yaml.load(f.read())


def validate_spec(log, spec_patterns, pattern_name, spec):
    """
    Validate syntax of a given 'spec' dictionary against the
    named spec_pattern.
    """
    pattern = spec_patterns[pattern_name]
    valid_spec = True
    log.debug("Validating spec against spec pattern '%s'\n Spec content:\n" % 
            (pattern_name, yaml.dumps(spec)))
    # test for required attributes
    required_attributes = [attr for attr in pattern if pattern[attr]['required']]
    for attr in required_attributes:
        if attr not in spec:
            log.debug("Required attributes for pattern '%s' : %s" %
                    (pattern_name, required_attributes))
            log.error("Required attribute '%s' not found in '%s' spec" %
                    (attr, pattern_name))
            valid_spec = False
    for attr in spec:
        log.debug("Considering attribute '%s'" % attr)
        # test if attribute is permitted
        if attr not in pattern:
            #print '  illegal attribute %s' % attr
            log.error("Attribute '%s' not permitted for spec pattern '%s'" %
                    (attr, pattern_name))
            valid_spec = False
            continue
        # test attribute type. ignore attr if value is None
        if spec[attr]:
            # (surely there must be a better way to extract the data type of
            # and object as a string)
            spec_attr_type = re.sub(r"<type '(\w+)'>", '\g<1>', str(type(spec[attr])))
            #print spec_attr_type
            #print type(pattern[attr]['atype'])
            log.debug("Spec attribute type: '%s'" % spec_attr_type)
            # simple attribute pattern
            if isinstance(pattern[attr]['atype'], str):
                log.debug("Pattern attribute type: '%s'" % pattern[attr]['atype'])
                if spec_attr_type != pattern[attr]['atype']:
                    #print '  attribute type must be %s' % pattern[attr]['atype']
                    log.error("Attribute '%s' must be of type '%s'" %
                            (attr, pattern[attr]['atype']))
                    valid_spec = False
                    continue
            else:
                # complex attribute pattern
                valid_types = pattern[attr]['atype'].keys()
                log.debug("Pattern attribute types: '%s'" % valid_types)
                #print valid_types
                if not spec_attr_type in valid_types: 
                    #print '  attribute type must be %s' % valid_types
                    log.error("Attribute '%s' must be one of type '%s'" %
                            (attr, valid_types))
                    valid_spec = False
                    continue
                atype = pattern[attr]['atype'][spec_attr_type]
                # test attributes values
                if atype and 'values' in atype:
                    log.debug("Allowed values for attrubute '%s': %s" %
                            (attr, atype['values']))
                    if not spec[attr] in atype['values']:
                        #print '  attribute value must be in %s' % atype['values']
                        log.error("Value of attribute '%s' must be one of '%s'"
                                % (attr, atype['values']))
                        valid_spec = False
                        continue
                    # assign 'default' value
                    if 'default' in atype and not spec[attr]:
                        log.debug("Assigning value '%s' to attrubute '%s'" %
                                (attr, atype['default']))
                        spec[attr] = atype['default']
    return valid_spec
