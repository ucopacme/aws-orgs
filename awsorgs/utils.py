"""Utility functions used by the various awsorgs modules"""

import os
import sys
import pkg_resources
import threading
import Queue # python 3 alert!

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
        rkey:    (optional) name of key referencing a value to return
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


def search_spec(spec, search_key, recurse_key):
    """
    Recursively scans spec structure and returns a list of values
    keyed with 'search_key' or and empty list.  Assumes values
    are either list or str.
    """
    value = []
    if search_key in spec and spec[search_key]:
        if isinstance(spec[search_key], str):
            value.append(spec[search_key])
        else:
            value += spec[search_key]
    if recurse_key in spec and spec[recurse_key]:
        for child_spec in spec[recurse_key]:
            value += search_spec(child_spec, search_key, recurse_key)
    return sorted(value)


def ensure_absent(spec):
    """
    test if an 'Ensure' key is set to absent in dictionary 'spec'
    """
    if 'Ensure' in spec and spec['Ensure'] == 'absent': return True
    return False


def munge_path(default_path, spec):
    """
    Return formated 'Path' attribute for use in iam client calls. 
    Prepend the 'default_path'.
    """
    if 'Path' in spec and spec['Path']:
        return "/%s/%s/" % (default_path, spec['Path'])
    return "/%s/" % default_path


def get_logger(args):
    """
    Setup logging.basicConfig from args.
    Return logging.Logger object.
    """
    # log level
    log_level = logging.CRITICAL
    if args['--verbose'] or args['report'] or args['--boto-log']:
        log_level = logging.INFO
    if args['--debug']:
        log_level = logging.DEBUG
    # log format
    log_format = '%(name)s: %(levelname)-9s%(message)s'
    if args['report']:
        log_format = '%(message)s'
    if args['--debug']:
        log_format = '%(name)s: %(levelname)-9s%(funcName)s():  %(message)s'
    if (not args['--exec'] and not args['report']):
        log_format = '[dryrun] %s' % log_format
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
        errmsg = ("The Organization Master Account Id '%s' does not match the "
                "'master_account_id' set in the spec-file" % master_account_id)
        raise RuntimeError(errmsg)
    return


def validate_spec_file(log, spec_file, pattern_name):
    """
    Validate spec-file is properly formed.
    """
    log.debug("loading spec file '%s'" % spec_file)
    validation_patterns = load_validation_patterns(log)
    with open(spec_file) as f:
        spec = yaml.load(f.read())
    log.debug("calling validate_spec() for pattern '%s'" % pattern_name)
    if validate_spec(log, validation_patterns, pattern_name, spec):
        return spec
    else:
        log.critical("Spec file '%s' failed syntax validation" % spec_file)
        sys.exit(1)


# QUESTION: I'm loading a data file by name.  It is part of the project and
# explicitly installed by setup.py.  but in code, should I define it as
# a constant insted of just loading a str? where should I declare this 
# constant?
def load_validation_patterns(log):
    """
    Return dict of patterns for use when validating specification syntax
    """
    PATTERN_FILE = 'data/spec-validation-patterns.yaml'
    log.debug("loading file: '%s'" % PATTERN_FILE)
    filename =  os.path.abspath(pkg_resources.resource_filename(__name__, PATTERN_FILE))
            #__name__, '../data/spec-validation-patterns.yaml'))
    with open(filename) as f:
        return yaml.load(f.read())


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


def queue_threads(log, sequence, func, f_args=(), thread_count=20):
    """generalized abstraction for running queued tasks in a thread pool"""

    def worker(*args):
        log.debug('%s: q.empty: %s' % (threading.current_thread().name, q.empty()))
        while not q.empty():
            log.debug('%s: task: %s' % (threading.current_thread().name, func))
            item = q.get()
            log.debug('%s: processing item: %s' % (threading.current_thread().name, item))
            func(item, *args)
            q.task_done()

    q = Queue.Queue()
    for item in sequence:
        log.debug('queuing item: %s' % item)
        q.put(item)
    log.debug('queue length: %s' % q.qsize())
    for i in range(thread_count):
        t = threading.Thread(target=worker, args=f_args)
        t.setDaemon(True)
        t.start()
    q.join()

