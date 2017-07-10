"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='aws-orgs',
    version='0.0.1.dev1',
    description='Tools to manage AWS Organizations',
    long_description=long_description,
    url='https://github.com/ashleygould/aws-orgs',
    author='Ashley Gould',
    author_email='agould@ucop.edu',
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: System Administrators',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='aws organizations',
    packages=find_packages(exclude=['scratch', 'notes', 'sample_input']),
    install_requires=['boto3, docopt'],
)
