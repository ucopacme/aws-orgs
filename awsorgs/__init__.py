
import os
import boto3


def ensure_absent(spec):
    """
    test if an 'Ensure' key is set to absent in dictionary 'spec'
    """
    if 'Ensure' in spec and spec['Ensure'] == 'absent': return True
    return False


def lookup(dlist, lkey, lvalue, rkey=None):
    """
    Use a known key:value pair to lookup a dictionary in a list of
    dictionaries.  Return the dictonary or None.  If rkey is provided,
    return the value referenced by rkey or None.  If more than one
    dict matches, raise an error.
    args:
        dlist:   lookup table -  a list of dictionaries
        lkey:    name of key to use as lookup criteria
        lvalue:  value to use as lookup criteria
        key:     (optional) name of key referencing a value to return
    """
    items = [d for d in dlist
             if lkey in d
             and d[lkey] == lvalue]
    if not items:
        return None
    if len(items) > 1:
        raise RuntimeError(
            "Data Error: lkey:lvalue lookup matches multiple items in dlist"
        )
    if rkey:
        if rkey in items[0]:
            return items[0][rkey]
        return None
    return items[0]


def logger(log, message):
    if message:
        log.append(message)
    return


def get_root_id(org_client):
    """
    Query deployed AWS Organization for its Root ID.
    """
    roots = org_client.list_roots()['Roots']
    if len(roots) >1:
        raise RuntimeError(
          "org_client.list_roots returned multiple roots.  Go figure!")
    return roots[0]['Id']


def validate_master_id(org_client, spec):
    """
    Don't mangle the wrong org by accident
    """
    master_account_id = org_client.describe_organization(
      )['Organization']['MasterAccountId']
    if master_account_id != spec['master_account_id']:
        errmsg = ("""The Organization Master Account Id '%s' does not
          match the 'master_account_id' set in the spec-file.  
          Is your '--profile' arg correct?""" % master_account_id)
        raise RuntimeError(errmsg)
    return


def get_client_for_assumed_role(service_name, account_id,
        role_name, region_name=None):
    """
    Get temporary sts assume_role credentials for account.
    Return boto3 client object with assumed role credentials attached.
    """
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + role_name
    role_session_name = account_id + '-' + role_name
    sts_client = boto3.client('sts')
    credentials = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name
            )['Credentials']
    return boto3.client(
            service_name,
            aws_access_key_id = credentials['AccessKeyId'],
            aws_secret_access_key = credentials['SecretAccessKey'],
            aws_session_token = credentials['SessionToken'],
            region_name=region_name)



