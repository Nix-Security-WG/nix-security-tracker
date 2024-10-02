# This script creates `.credentials/` and populates it with some fake secrets

mkdir .credentials
python3 -c 'import secrets; print(secrets.token_hex(100))' > .credentials/SECRET_KEY
echo bar > .credentials/GH_CLIENT_ID
echo baz > .credentials/GH_SECRET
echo quux > .credentials/GH_WEBHOOK_SECRET
