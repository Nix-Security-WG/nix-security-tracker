#!/usr/bin/env nix-shell
#!nix-shell -i bash -p awscli pv

set -eo pipefail

# We are using Garage.
export ENDPOINT_URL="https://s3.dc1.lahfa.xyz"
export AWS_DEFAULT_REGION="garage"

# Show credentials (they are half-hidden)
aws configure list

# Inspired from https://github.com/gabfl/pg_dump-to-s3/blob/main/pg_dump-to-s3.sh
# and adapted for our needs.

S3_PATH="staging-sectracker-db"
DELETE_AFTER="1 day"

NOW=$(date +"%Y-%m-%d-at-%H-%M-%S")
DELETION_TIMESTAMP=`[ "$(uname)" = Linux ] && date +%s --date="-$DELETE_AFTER"` # Maximum date (will delete all files older than this date)

echo "Backup in progress..."

DBS=('web-security-tracker')

for db in "${DBS[@]}"; do
  FILENAME="$NOW"_"$db"

  echo "-> backing up $db..."

  ssh root@sectracker.nixpkgs.lahfa.xyz "sudo -u postgres pg_dump -Z5 -O -Fc $db" | pv | aws --endpoint-url "$ENDPOINT_URL" s3 cp - s3://$S3_PATH/$FILENAME

  echo "$db has been backed up."
done

echo "Garbage collecting previous dumps..."

aws --endpoint-url "$ENDPOINT_URL" s3 ls s3://$S3_PATH/ | while read -r line; do
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
            aws --endpoint-url "$ENDPOINT_URL" s3 rm s3://$S3_PATH/$FILENAME
        fi
    fi
done;
