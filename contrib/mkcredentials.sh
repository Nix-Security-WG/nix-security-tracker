# This script creates `.credentials/` and populates it with some fake secrets

mkdir .credentials
echo foo > .credentials/SECRET_KEY
echo bar > .credentials/GH_CLIENT_ID
echo baz > .credentials/GH_SECRET
echo quux > .credentials/GH_WEBHOOK_SECRET
