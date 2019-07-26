AWS-ORGS Configuration
======================


Initial Configuration
---------------------

AWS-ORGS provides a helper script ``awsorgs-spec-init``.  This script generates
an initial ``config.yaml`` and a full set of example spec files.  By default
these are installed under ``~/.awsorgs``::

  > awsorgs-spec-init
  find ~/.awsorgs
  ~/.awsorgs/config.yaml
  ~/.awsorgs/spec.d/accounts.yaml
  ~/.awsorgs/spec.d/common.yaml
  ~/.awsorgs/spec.d/custom_policies.yaml
  ~/.awsorgs/spec.d/delegations.yaml
  ~/.awsorgs/spec.d/groups.yaml
  ~/.awsorgs/spec.d/local_users.yaml
  ~/.awsorgs/spec.d/orgs.yaml
  ~/.awsorgs/spec.d/policy-sets.yaml
  ~/.awsorgs/spec.d/service_control_policies.yaml
  ~/.awsorgs/spec.d/teams.yaml
  ~/.awsorgs/spec.d/users.yaml

Run ``awsorgs-spec-init --help`` for options on how to install to alternate locations.


config.yaml
-----------

Most CLI commands make use of a per-user config file for basic paramaters.  The
default location is `~/.awsorgs/config.yaml`.  This file supplies the values
for required cli option parameters::

  --spec-dir
  --master-account-id
  --auth-account-id
  --org-access-role

Example:

.. literalinclude:: ../../awsorgs/spec_init_data/config.yaml


Copy this file to your home directory (or run ``awsorgs-spec-init``) and edit
parameter values to suit your AWS Organization.


Spec Files
----------

AWS-ORGS makes use of a complex of YAML formatted resource specification files.
The spec files are used by aws-orgs commands to deploy and maintain AWS accounts and 
IAM resources across your Organization.

A set of example spec files gets installed on your system when you run
``awsorg-spec-init``.  Each or the example spec files contains complete
documentation of spec attributes.  Edit these to suit your AWS Organization.  

The default spec directory is `~/.awsorgs/spec.d`.  If you choose a non-default
location, be sure to update the ``spec_dir`` parameter in your ``config.yaml``.

.. toctree::
   :hidden:

   spec_files


Shared Specs
************

:ref:`spec_files:common.yaml`
  Top level spec attributes common to all tools.


:ref:`spec_files:teams.yaml`
  these are used as attributes in other spec objects:

  - accounts
  - users
  - local_users



``awsorgs``
***********

:ref:`spec_files:organizational_units.yaml`

:ref:`spec_files:service_control_policies.yaml`



``awsaccounts``
***************

:ref:`spec_files:accounts.yaml`



``awsauth``
***********

:ref:`spec_files:users.yaml`

:ref:`spec_files:groups.yaml`

:ref:`spec_files:delegations.yaml`

:ref:`spec_files:policy_sets.yaml`

:ref:`spec_files:custom_policies.yaml`

:ref:`spec_files:local_users.yaml`


