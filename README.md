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
  name = "nix-security-tracker";
  ensureDBOwnership = true;
}];
```

### Set up GitHub authentication

1. Create a new or select an existing GitHub organisation to associate with the application
2. For your GitHub user, in **Developer Settings**, generate a new [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

   This is not strictly necessary just to run the service, but allows for more API calls and is therefore important for a production deployment.

   - Generate new token
     - In **Resource owner** select the GitHub organisation associated with the application
     - In **Repository access** select **Public Repositories (read-only)**
     - No other permissions are required
   - Store the value in `.credentials/GH_TOKEN`

3. In the GitHub organisation settings, [create an OAuth application](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app):

   - In **Personal access tokens** approve the request
   - In **Developer settings** OAuth Apps, create a new application

     Store the **Client ID** in `.credentials/GH_CLIENT_ID`

   - In the application settings **Generate a new client secret**

     Store the value in `.credentials/GH_SECRET`

You only need real GitHub credentials to use the OAuth login feature.
To get going quickly, set any values for secrets required by the server:

```console
mkdir .credentials
echo foo > .credentials/SECRET_KEY
echo bar > .credentials/GH_CLIENT_ID
echo baz > .credentials/GH_SECRET
```

### Set up Github App webhooks

For now, we require a GitHub webhook to receive push notifications when team memberships change. To configure the GitHub app and the webhook:

1. In the GitHub organisation settings:

- In **Code, planning, and automation** Webhooks, create a new webhook:
  - In **Payload URL**, input "https://<APP_DOMAIN>/github-webhook".
  - In **Content Type** choose **application/json**.
  - Generate a token and put in **Secret**. This token should be in `./credentials/GH_WEBHOOK_SECRET`.
  - Choose **Let me select individual events**
    - Deselect **Pushes**.
    - Select **Memberships**.

## Reseting the database

Set up the database with known-good values to play around with:

```console
./contrib/reset.sh
```

Start the server and its workers:

```console
hivemind
```

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

Whenever you add a field in the database schema, run:

```console
manage makemigrations
```

Then before starting the server again, run:

```
manage migrate
```

This is the default Django workflow.

## Fixtures

If you haven't changed the schema, using fixtures is faster than resetting the database completely.

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
Django will look inside the app folders for a fixture to match this name.

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

Evaluating Nixpkgs happens on a local Git repository.
Start with creating a checkout:

```console
manage initiate_checkout
```

The service will then listen on creation of channel entries in the database.
These are made by the following command, which gets all recent channel branch evaluations and fetches the corresponding commits to the local Git repository:

```console
manage fetch_all_channels
```

To run an evaluation of Nixpkgs manually, for example of the `nixos-23.11` channel:

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
