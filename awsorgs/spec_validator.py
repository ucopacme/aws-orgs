#!/usr/bin/python

import os
import pkg_resources
import yaml
import re

def load_specification_formats():
    filename =  os.path.abspath(
            pkg_resources.resource_filename(
            __name__, '../data/specification-formats.yaml'))
    with open(filename) as f:
        specification_formats = yaml.load(f.read())
    return specification_formats 


def validate_spec(specification_formats, format_name, spec):
    # test for required attributes
    required_attributes = [attr for attr in specification_formats[format_name]
            if specification_formats[format_name][attr]['required']]
    for attr in required_attributes:
        if attr not in spec:
            print "  required attribute %s not found" % attr
    for attr in spec:
        #print attr
        # test if attribute is permitted
        if attr not in specification_formats[format_name]:
            print '  illegal attribute %s' % attr
            continue
        if spec[attr]:
            format_attr = specification_formats[format_name][attr]
            # test attribute type
            spec_attr_type = re.sub(r"<type '(\w+)'>", '\g<1>', str(type(spec[attr])))
            #print spec_attr_type
            #print type(format_attr['atype'])
            # simple attribute format
            if isinstance(format_attr['atype'], str):
                if spec_attr_type != format_attr['atype']:
                    print '  attribute type must be %s' % format_attr['atype']
                    continue
            else:
                # complex attribute format
                valid_types = format_attr['atype'].keys()
                #print valid_types
                if not spec_attr_type in valid_types: 
                    print '  attribute type must be %s' % valid_types
                    continue
                atype = format_attr['atype'][spec_attr_type]
                #print atype
                if atype:
                # test attributes values
                    if 'values' in atype and not spec[attr] in atype['values']:
                        print '  attribute value must be in %s' % atype['values']
                        continue
                    # assign 'default' value
                    if 'default' in atype and not spec[attr]:
                        spec[attr] = atype['default']



specification_formats = load_specification_formats()
spec_file = '/home/ashely/aws/spec/auth-spec.yaml'
format_name = 'delegations'
specifications = yaml.load(open(spec_file).read())
for spec in specifications[format_name]:
    #print
    #print yaml.dump(spec)
    validate_spec(specification_formats, format_name, spec)





