#!/usr/bin/python

# Consider:
# rename 'formats' -> 'patterns'

import os
import pkg_resources
import yaml
import re
from awsorgs.utils import *


spec_patterns = load_spec_patterns()
spec_file = '/home/ashely/aws/spec/auth-spec.yaml'
pattern_name = 'delegations'
specs = yaml.load(open(spec_file).read())
for spec in specs[pattern_name]:
    #print
    #print yaml.dump(spec)
    print validate_spec(log, spec_patterns, pattern_name, spec)



"""
Notes:
