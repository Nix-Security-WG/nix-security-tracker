# Nixpkgs Security Tracker

The **Nixpkgs Security Tracker** is a web service for managing information on vulnerabilities in software distributed through Nixpkgs.

# Hacking

The service is implemented in Python using [Django](https://www.djangoproject.com/).

## Quick start

Start a development shell:

```console
nix-shell
```

Or set up [`nix-direnv`](https://github.com/nix-community/nix-direnv) on your system and run `direnv allow` to enter the development environment automatically when entering the project directory.

Currently only [PostgreSQL](https://www.postgresql.org/) is supported as a database.
You can set up a database on NixOS like this:

```
services.postgresql.enable = true;
services.postgresql.ensureDatabases = [ "nix-security-tracker" ];
services.postgresql.ensureUsers = [{
  name = "youruser";
  ensureDBOwnership = true;
}];
```

Set any values for secrets required by the server:

```console
mkdir .credentials
echo foo > .credentials/SECRET_KEY
echo bar > .credentials/GH_CLIENT_ID
echo baz > .credentials/GH_SECRET
```

You only need actual GitHub credentials to use the OAuth login feature.

Set up the database with known-good values to play around with:

```console
./contrib/reset.sh
```

Call `manage runserver` and open <http://localhost:8000>.

## Running tests

Run all integration tests:

```console
nix-build -A tests
```

Run a smoke test:

```console
nix-build -A tests.vm-basic
```

Interact with the involved virtual machines in a test:

```
$(nix-build -A tests.vm-basic.driverInteractive)/bin/nixos-test-driver
```

## Changing the database schema

Whenever you add a field in the database schema, call `manage makemigrations`.
Then run `manage migrate` before starting the server again.
This is the default Django workflow.

## Fixtures

Using fixtures is faster than resetting the database completely, especially if you haven't changed the schema.

Remove all data:

```console
manage flush
```

A fixture file is availble for the `shared` app, located at `src/website/shared/fixtures/sample.json`.

To load it into the database:

```console
manage loaddata sample
```

Where `sample` is the name of the fixture JSON file.
Django will look inside the app folders for a fixture folders to match this name.

To create (or update) a fixture file:

```console
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

Get a full evaluaton of Nixpkgs, for example of the `nixos-23.11` channel:

```console
./contrib/get-all-hydra-jobs.sh -I nixpkgs=channel:nixos-23.11
```

and take note of the Git revision of Nixpkgs you're evaluating.

For a channel, this can be found in the associated `git-revision` file, for example <https://channels.nixos.org/nixos-23.11/git-revision>.

The script will write to `$PWD/evaluation.jsonl`.
This takes ~30 min on a fast machine and needs lots of RAM.

To get it faster, use this temporary file:

```console
wget https://files.lahfa.xyz/private/evaluation.jsonl.zst
zstd -d evaluation.jsonl.zst -o ./contrib/evaluation.jsonl
```

Before ingesting, call `manage runsever` and manually create a "Nix channel":

```console
manage register_channel '<null>' nixos-unstable UNSTABLE
```

The "Channel branch" field must match the parameter passed to `ingest_manual_evaluation`, which is `nixos-unstable` here.
All other fields can have arbitrary values.

Add 100 entries for one evaluation of a channel branch, and provide the commit hash of that evaluation as well as the channel branch:

```console
manage ingest_manual_evaluation d616185828194210bfa0e51980d78a8bcd1246cc nixos-unstable evaluation.jsonl --subset 100
```

Not passing `--subset N` will take about an hour and produce ~600 MB of data.

## Staging deployment

If you have your SSH keys set up on the staging environment (and can connect through IPv6), you can deploy the service with:

```console
./staging/deploy.sh
```

### Adding SSH keys

Add your SSH keys to `./staging/configuration.nix` and let existing owners deploy them.
