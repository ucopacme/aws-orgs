aws-orgs spec-file setup
========================


See the ``samples/`` directory for anotated examples of spec-file syntax.

Copy example spec files into your `spec_dir` location and edit as appropriate
to your site.  The default spec directory is `~/.awsorgs/spec.d`.

Most CLI commands make use of a config file for basic paramaters.
The default location is `~/.awsorgs/config.yaml`.  Example::

  # Path to yaml spec files directory.  Any yaml files under this
  # dirctory (recursive) are parsed as spec files.
  spec_dir: ~/git-repos/awsorgs_specfiles/my_org

  # An AWS role name which permits cross account access to all accounts.
  org_access_role: awsauth/OrgAdmin

  # AWS account Id for the Organization master account.  This must be in quotes.
  master_account_id: '121212121212'

  # AWS account Id for the Central Auth account.  This must be in quotes.
  auth_account_id: '343434343434'


