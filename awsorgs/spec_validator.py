#!/usr/bin/python

# Consider:
# rename 'formats' -> 'patterns'

import os
import pkg_resources
import yaml
import re
from awsorgs.utils import *

#def load_spec_patterns():
#    """
#    Return dict of patterns for use when validating specification syntax
#    """
#    filename =  os.path.abspath(pkg_resources.resource_filename(
#            __name__, '../data/spec-patterns.yaml'))
#    with open(filename) as f:
#        return yaml.load(f.read())
#
#
#def validate_spec(spec_patterns, pattern_name, spec):
#    """
#    Validate syntax of a given 'spec' dictionary against the
#    named spec_pattern.
#    """
#    # test for required attributes
#    required_attributes = [attr for attr in spec_patterns[pattern_name]
#            if spec_patterns[pattern_name][attr]['required']]
#    for attr in required_attributes:
#        if attr not in spec:
#            print "  required attribute %s not found" % attr
#    for attr in spec:
#        #print attr
#        # test if attribute is permitted
#        if attr not in spec_patterns[pattern_name]:
#            print '  illegal attribute %s' % attr
#            continue
#        if spec[attr]:
#            pattern_attr = spec_patterns[pattern_name][attr]
#            # test attribute type
#            spec_attr_type = re.sub(r"<type '(\w+)'>", '\g<1>', str(type(spec[attr])))
#            #print spec_attr_type
#            #print type(pattern_attr['atype'])
#            # simple attribute pattern
#            if isinstance(pattern_attr['atype'], str):
#                if spec_attr_type != pattern_attr['atype']:
#                    print '  attribute type must be %s' % pattern_attr['atype']
#                    continue
#            else:
#                # complex attribute pattern
#                valid_types = pattern_attr['atype'].keys()
#                #print valid_types
#                if not spec_attr_type in valid_types: 
#                    print '  attribute type must be %s' % valid_types
#                    continue
#                atype = pattern_attr['atype'][spec_attr_type]
#                #print atype
#                if atype:
#                # test attributes values
#                    if 'values' in atype and not spec[attr] in atype['values']:
#                        print '  attribute value must be in %s' % atype['values']
#                        continue
#                    # assign 'default' value
#                    if 'default' in atype and not spec[attr]:
#                        spec[attr] = atype['default']
#


spec_patterns = load_spec_patterns()
spec_file = '/home/ashely/aws/spec/auth-spec.yaml'
pattern_name = 'delegations'
specs = yaml.load(open(spec_file).read())
for spec in specs[pattern_name]:
    #print
    #print yaml.dump(spec)
    print validate_spec(spec_patterns, pattern_name, spec)





