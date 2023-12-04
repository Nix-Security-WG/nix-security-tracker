# NixOS Security Tracker

The **NixOS Security Tracker** is a django based application for following vulnerabilities in NixOS packages, displaying their details.

# Hacking

Start a development shell:

```console
nix-shell
```

Show helper commands:

```console
./src/website/manage.py --help
```

Start server:

```console
./src/website/manage.py  runserver
```

systemd automatically sets `$CREDENTIALS_DIRECTORY` to this location:

```
ls ./.credentials
```

On first start this will not exist. Set these values:

```console
echo foo > .credentials/SECRET_KEY
echo bar > .credentials/GH_CLIENT_ID
echo baz > .credentials/GH_SECRET
```

You only need actual GitHub credentials to use the login feature.

The database is written to `./src/website`.

- On the first start, run `migrate` to create the schema.
- Run `ingest_bulk_cve`. This will take about an hour and produce ~500 MB of data.
- Call `runserver` and check `https://localhost:8000`.

Whenever you add a field in the database schema, call `makemigrations`.
Then run `migrate` before starting the server again.
This is the default Django workflow.
