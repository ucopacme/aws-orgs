#!/usr/bin/env python
import boto3


def get_passwd_policy():
    client = boto3.client('iam')
    try:
        return client.get_account_password_policy()['PasswordPolicy']
    except client.exceptions.NoSuchEntityException:
        return "password policy not implemented"

def set_passwd_policy():
    client = boto3.client('iam')
    client.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=180,
        PasswordReusePrevention=6,
        #HardExpiry=True|False
    )
    return

def delete_passwd_policy():
    client = boto3.client('iam')
    client.delete_account_password_policy()
    return 



if __name__ == '__main__':
    #response = set_passwd_policy()
    #response = get_passwd_policy()
    #print(yamlfmt(response))
    #response = delete_passwd_policy()
    #response = get_passwd_policy()
    #print(yamlfmt(response))
