Steps for Publishing this Package to PyPI
=========================================

Follow these steps to build and upload the package to PyPI.  For more info,
visit https://packaging.python.org/tutorials/packaging-projects


Prerequisites
-------------

- You must have access rights to post to both ``test.pypi.org`` and ``pypi.org``
- You must have `maintainer` status for this project on both ``test.pypi.org`` and ``pypi.org``
- Your python environment must have the latest updates to the required tools::

  > pip install -U pip setuptools wheel twine


Build the new release
---------------------

After merging a pull request on Github:

1. Pull the new commits into your local master branch::

     > git checkout master
     > git pull ucopacme master

#. Edit ``awsorgs/__init__.py`` and update the ``__version__`` parameter to the new tag::

     > git diff 
      
     -__version__ = '0.3.0.dev0'
     +__version__ = '0.3.0'
 
#. Build a distributable package with the ``setup.py`` script::

     > python setup.py sdist bdist_wheel
     > ls -1 dist/
     aws-orgs-0.3.0-py3-none-any.whl
     aws-orgs-0.3.0.tar.gz


Validate distribution
---------------------

#. Upload the new dist to the test PyPI site::

     > twine upload --repository-url https://test.pypi.org/legacy/ dist/*
     Enter your username: agould
     Enter your password: ************
     Uploading distributions to https://test.pypi.org/legacy/
     Uploading aws-orgs-0.3.0.dev1-py3-none-any.whl
     Uploading aws-orgs-0.3.0-py3-none-any.whl

#. Visit ``test.pypi.org`` and verify your release: https://test.pypi.org/project/aws-orgs/

#. Install the package into a clean python virtual environment::

     > python -m venv package-test
     > source package-test/bin/activate
     > pip install --index-url https://test.pypi.org/simple/ --no-deps aws-orgs
     Looking in indexes: https://test.pypi.org/simple/
     Collecting aws-orgs
     Successfully installed aws-orgs-0.3.0

#. Verify the install::

     > pip show aws-orgs 
     Name: aws-orgs
     Version: 0.3.0
     Summary: Tools for working with AWS Organizations
     Home-page: https://github.com/ucopacme/aws-orgs


Publish to public PyPI
----------------------

1. Upload to real PyPI site::

     > twine upload dist/*
     Enter your password: 
     Uploading distributions to https://upload.pypi.org/legacy/
     Uploading aws-orgs-0.3.0-py3-none-any.whl
     Uploading aws-orgs-0.3.0.tar.gz

#. Visit ``pypi.org`` and verify your release: https://pypi.org/project/aws-orgs/


Tag and push to Github
----------------------

#. Be sure to commit the version update any other changes you made during package validation::

     > git commit -am 'release 0.3.0'
     [master 04c3946] release 0.3.0

#. Create a git tag for the new release::

     > git tag -a -m 'Release 0.3.0'  0.3.0

#. Push to master on github along with the new tag::

     > git push ucopacme master --tags
     To github.com:ucopacme/aws-orgs.git
        0035e5f..04c3946  master -> master
      * [new tag]         0.3.0 -> 0.3.0


