#!/usr/bin/env python

'''
Install initial aws-orgs config and spec files into user's home directory

Usage:
  awsorgs-spec-init [-h | --help] [--config File] [--spec-dir PATH]

Options:
  -h, --help        Show this message and exit.
  --config FILE     Where to install AWS Org config file
                    [Default: ~/.awsorgs/config.yaml].
  --spec-dir PATH   Where to install AWS Org specification files
                    [Default: ~/.awsorgs/spec.d].

'''

import os
import pkg_resources
from docopt import docopt

def main():
    args = docopt(__doc__)
    print(args)
    homedir = os.environ.get('HOME')
    source_config_file =  os.path.abspath(
        pkg_resources.resource_filename(
            __name__,
            '../spec_init_data/config.yaml'
        )
    )
    source_spec_dir =  os.path.abspath(
        pkg_resources.resource_filename(
            __name__,
            '../spec_init_data/spec.d'
        )
    )
    print(source_config_file, source_spec_dir)


if __name__ == "__main__":
    main()

