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

Call `manage runserver` and open <https://localhost:8000>.

Run `manage createsuperuser` to access the admin panel at <https://localhost:8000/admin> and manually edit database entries.

Whenever you add a field in the database schema, call `makemigrations`.
Then run `migrate` before starting the server again.
This is the default Django workflow.

# Ingesting data for testing

To play around with it, you need some data.

## CVEs

Add 100 CVE entries to the database:

```console
manage ingest_bulk_cve --test
```

This will take a few minutes on an average machine.
Not passing `--test` will take about an hour and produce ~500 MB of data.

## Nixpkgs evaluations

Get a full evaluaton of Nixpkgs:

```console
./contrib/get-all-hydra-jobs.sh -I channel:nixos-23.11
```

The script will write to `$PWD/evalution.json`.
This takes ~30 min on a fast machine and needs lots of RAM.

To get it faster, use this temporary file:

```console
wget https://files.lahfa.xyz/private/evaluation.jsonl.zst
zstd -d evaluation.jsonl.zst
```

Before ingesting, call `manage runsever` and manually create a "Nix channel": <http://127.0.0.1:8000/admin/shared/nixchannel/>

The "Channel branch" field must match the parameter passed to `ingest_manual_evaluation`, which is `nixos-unstable` here.
All other fields can have arbitrary values.

Ingest the data for one evaluation of a channel branch, and provide the commit hash of that evaluation as well as the channel branch:

```console
manage ingest_manual_evaluation d616185828194210bfa0e51980d78a8bcd1246cc nixos-unstable evaluation.jsonl
```
