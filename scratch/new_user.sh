#!/bin/bash
set -x

ROLE="awsauth/OrgAdmin"
REPORTDIR="$HOME/tmp/loginprofiles"
USER=$1
MODE=$2
EMAIL=$3

REPORT=$REPORTDIR/$USER
awsloginprofile $USER --${MODE} --role $ROLE 2>&1 | tee $REPORT

if [ -n "$EMAIL" ]; then
  echo | mail -s 'login profile' -c agould@ucop.edu -a $REPORT $EMAIL
fi
