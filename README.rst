This project is an attempt to provision AWS Oranizations resources based on
structured imput files.

awsauth.py: A module to manage users, group, and roles for cross account authentication in
AWS.



git clone https://github.com/ashleygould/aws-orgs
pip install --user -e aws-orgs/

pip uninstall aws-orgs
rm ~/.local/bin/{awsorgs,awsaccounts,awsauth}
