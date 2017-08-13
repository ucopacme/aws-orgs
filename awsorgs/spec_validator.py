#!/usr/bin/python

import yaml
import re

delegation_format = """
delegation:
  RoleName:
    atype: str
    required: True
  Ensure:
    atype: str
    required: False
    values:
      - present
      - absent
  Description:
    atype: str
    required: False
  #TrustingAccount:
  #  - atype: str
  #    required: False
  #    values:
  #      - ALL
  #  - atype: list
  #    required: False
  TrustedGroup:
    atype: str
    required: True
  RequireMFA:
    atype: bool
    required: False
    #default: True
  Policies:
    atype: list
    required: False
"""


spec_types = yaml.load(delegation_format)
#print spec_types['delegation']['RoleName']['atype']

spec_file = '/home/ashely/aws/spec/auth-spec.yaml'
spec = yaml.load(open(spec_file).read())
d_spec = spec['delegations'][0]
#print yaml.dump(d_spec)


required_attributes = [attr for attr in spec_types['delegation']
        if spec_types['delegation'][attr]['required']]
#print required_attributes
for attr in required_attributes:
    if attr not in d_spec:
        print "  required attribute %s not found" % attr

for attr in d_spec:
    print attr
    if attr not in spec_types['delegation']:
        print '  illegal attribute %s' % attr
    else:
        if not re.search(spec_types['delegation'][attr]['atype'], str(type(d_spec[attr]))):
            print type(d_spec[attr])
            print '  attribute type must be %s' % spec_types['delegation'][attr]['atype']
