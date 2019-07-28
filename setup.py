"""aws-orgs setup"""

from awsorgs import __version__
from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='aws-orgs',
    version=__version__,
    description='Tools to manage AWS Organizations',
    long_description=long_description,
    url='https://github.com/ucopacme/aws-orgs',
    author='Ashley Gould',
    author_email='agould@ucop.edu',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='aws organizations',
    packages=find_packages(exclude=['scratch', 'notes']),
    install_requires=[
        'boto3', 
        'docopt', 
        'PyYAML', 
        'passwordgenerator',
        'cerberus',
    ],
    package_data={
        'awsorgs': [
            'data/*',
            'spec_init_data/*',
            'spec_init_data/spec.d/*',
        ],
    },
    entry_points={
        'console_scripts': [
            'awsorgs=awsorgs.orgs:main',
            'awsaccounts=awsorgs.accounts:main',
            'awsauth=awsorgs.auth:main',
            'awsloginprofile=awsorgs.loginprofile:main',
            'awsorgs-accessrole=awsorgs.tools.accessrole:main',
            'awsorgs-spec-init=awsorgs.tools.spec_init:main',
        ],
    },

)
