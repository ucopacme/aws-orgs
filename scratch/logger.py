#!/usr/bin/python

import logging
log = logging.getLogger(__name__)
log.setLevel('INFO')
ch = logging.StreamHandler()
log.addHandler(ch)



token = 'blee'
log.info("Attempting to fall back to old starting token parser. For "
          "token: %s" % token)

