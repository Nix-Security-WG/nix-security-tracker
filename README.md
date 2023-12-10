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

## Fixtures

A fixture file is availble for the `shared` app, located at `src/website/shared/fixtures/sample.json`.

To load the data into the database:

```console
manage loaddata sample
```

Were `sample` is the name of fixture JSON file. Django will look inside the app folders for a fixture folders to match this name.

### Recreating fixture files

In case you want to recreate a fixture file:

```console
# Empty the database
manage flush

# Ingest CVE data
manage ingest_bulk_cve --test

# Register a Nix Channel in the database
manage register_channel <null> nixos-unstable UNSTABLE

# Ingest evaluation data
manage ingest_manual_evaluation d616185828194210bfa0e51980d78a8bcd1246cc nixos-unstable evaluation.jsonl

# Dump the database into the fixture file
manage dumpdata shared > src/website/shared/fixtures/sample.json
```

## Manual ingestion

### CVEs

Add 100 CVE entries to the database:

```console
manage ingest_bulk_cve --subset 100
```

This will take a few minutes on an average machine.
Not passing `--subset N` will take about an hour and produce ~500 MB of data.

### Nixpkgs evaluations

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

Before ingesting, call `manage runsever` and manually create a "Nix channel":

```console
src/website/manage.py register_channel <null> nixos-unstable UNSTABLE
```

The "Channel branch" field must match the parameter passed to `ingest_manual_evaluation`, which is `nixos-unstable` here.
All other fields can have arbitrary values.

Add 100 entries for one evaluation of a channel branch, and provide the commit hash of that evaluation as well as the channel branch:

```console
manage ingest_manual_evaluation d616185828194210bfa0e51980d78a8bcd1246cc nixos-unstable evaluation.jsonl --subset 100
```

Not passing `--subset N` will take about an hour and produce ~600 MB of data.

## Running tests

Run all integration tests:

```console
nix-build -A tests
```

Run a smoke test:

```console
nix-build -A tests.basic
```

Interact with the virtual machines in a test:

```
$(nix-build -A tests.basic.driverInteractive)/bin/nixos-test-driver
```
