#!/usr/bin/env nix-shell
#!nix-shell -i bash -p awscli pv

set -eo pipefail

# Inspired from https://github.com/gabfl/pg_dump-to-s3/blob/main/pg_dump-to-s3.sh
# and adapted for our needs.

S3_PATH="staging-sectracker-db"
DELETE_AFTER="7 days"

NOW=$(date +"%Y-%m-%d-at-%H-%M-%S")
DELETION_TIMESTAMP=`[ "$(uname)" = Linux ] && date +%s --date="-$DELETE_AFTER"` # Maximum date (will delete all files older than this date)

echo "Backup in progress..."

DBS=('web-security-tracker')

for db in "${DBS[@]}"; do
  FILENAME="$NOW_$db"

  echo "-> backing up $db..."

  ssh root@sectracker.nixpkgs.lahfa.xyz "sudo -u postgres pg_dump -Z1 -O -Fc $db" | pv | aws s3 cp - s3://$S3_PATH/$FILENAME

  echo "$db has been backed up."
done

echo "Garbage collecting previous dumps..."

aws s3 ls s3://$S3_PATH/ | while read -r line; do
    # Get file creation date
    createDate=`echo $line|awk {'print $1" "$2'}`
    createDate=`date -d"$createDate" +%s`

    if [[ $createDate -lt $DELETION_TIMESTAMP ]]
    then
        # Get file name
        FILENAME=`echo $line|awk {'print $4'}`
        if [[ $FILENAME != "" ]]
          then
            echo "Deleting $FILENAME"
            aws s3 rm s3://$S3_PATH/$FILENAME
        fi
    fi
done;
