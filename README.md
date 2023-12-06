# NixOS Security Tracker

The **NixOS Security Tracker** is a django based application for following vulnerabilities in NixOS packages, displaying their details.

# Hacking

Start a development shell:

```console
nix-shell
```

Or set up [`nix-direnv`](https://github.com/nix-community/nix-direnv) on your system and run `direnv allow` to enter the development environment automatically.

Show helper commands:

```console
./src/website/manage.py --help
```

> You may want to set an alias for convenience:
>
> ```console
> alias manage=./src/website/manage.py
> ```

Set any values for secrets required by the server:

```console
mkdir .credentials
echo foo > .credentials/SECRET_KEY
echo bar > .credentials/GH_CLIENT_ID
echo baz > .credentials/GH_SECRET
```

You only need actual GitHub credentials to use the OAuth login feature.

On the first start, run `manage migrate` to create the schema.
The database is written to `./tracker.sqlite3`.

Run `manage ingest_bulk_cve`.
This will take about an hour and produce ~500 MB of data.

Call `manage runserver` and open <https://localhost:8000>.

Run `manage createsuperuser` to access the admin panel at <https://localhost:8000/admin> and manually edit database entries.

Whenever you add a field in the database schema, call `makemigrations`.
Then run `migrate` before starting the server again.
This is the default Django workflow.
