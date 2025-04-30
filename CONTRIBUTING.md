# Contributing Guide

This document is for anyone wanting to contribute to the implementation of the security tracker.

## Overview

This file contains general contribution information, but the other directories in this repository have additional `README.md` files with more specific information relevant to their sibling files:

# Hacking

The service is implemented in Python using [Django](https://www.djangoproject.com/).

## Setting up credentials

The service connects to GitHub on startup, in order to manage permissions according to GitHub team membership in the configured organisation.

<details><summary>Create a Django secret key</summary>

```console
python3 -c 'import secrets; print(secrets.token_hex(100))' > .credentials/SECRET_KEY
```

</details>

<details><summary>Set up GitHub authentication</summary>

1.  Create a new or select an existing GitHub organisation to associate with the application

    - In the **Settings** tab under **Personal access tokens**, ensure that personal access tokens are allowed.
    - In the **Teams** tab, ensure there are at least two teams, corresponding to [`nixpkgs-committers`](https://github.com/orgs/nixos/teams/nixpkgs-committers) and [`security`](https://github.com/orgs/nixos/teams/security)

      These teams will be used for mapping user permissions.
      The actual names are arbitrary and can be configured in the service settings.

    - Put the organisation name and team names into `.settings.py` so it gets picked up :

      ```python
      GH_ORGANIZATION = "my-org"
      GH_COMMITTERS_TEAM = "team1"
      GH_SECURITY_TEAM = "team2"
      ```

      <!--
      TODO: this only works for the local dev environment. staging and prod still need work:
      https://github.com/Nix-Security-WG/nix-security-tracker/issues/239
      https://github.com/Nix-Security-WG/nix-security-tracker/issues/240
      https://github.com/Nix-Security-WG/nix-security-tracker/issues/285
      -->

2.  For your GitHub user, in **Developer Settings**, generate a new [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

    This is not strictly necessary just to run the service, but allows for more API calls and is therefore important for a production deployment.

    - Generate new token
      - In **Resource owner** select the GitHub organisation associated with the application
      - In **Repository access** select **Public Repositories (read-only)**
      - In **Permissions**, set **Members** permissions to **Read-only**
      - No other permissions are required
    - Store the value in `.credentials/GH_TOKEN`

3.  In the GitHub organisation settings, [register a GitHub application](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app):

    - In **Personal access tokens** approve the request under **Pending requests** if approval is required
    - In **Developer settings** GitHub Apps, create a new application

      - In **Repository Permissions** select **Administration (read-only)**, **Issues (read and write)** and **(Metadata: read-only)**.
      - In **Organization Permissions** select **Administration (read-only)** and **(Members: read-only)**.

      Store the **Client ID** in `.credentials/GH_CLIENT_ID`

    - In the application settings / **General** / **Generate a new client secret**

      Store the value in `.credentials/GH_SECRET`

    - In the application settings / **General** / **Private keys** / **Generate a private key**

      Store the value in `.credentials/GH_APP_PRIVATE_KEY`

    - In the application settings / **Install App**

      **Install** in the organisation account.

      <details><summary>If the account that shows up is your Developer Account</summary>

      You can delete and start over making sure that the context is the organisation account, or:

      - In the application settings / **Advanced**

        **Transfer ownership of this GitHub App** to the organisation account.

        </details>

    - In organisation settings / **Third-party Access** / **GitHub Apps** / **Installed GitHub Apps** / **<GH_APP_NAME>** / **Configure** page

      Check the URL, which has the pattern `https://github.com/organizations/<ORG_NAME>/settings/installations/<INSTALLATION_ID>`.

      Store the value **<INSTALLATION_ID>** in `.credentials/GH_APP_INSTALLATION_ID`.

</details>

<details><summary>Set up Github App webhooks</summary>

For now, we require a GitHub webhook to receive push notifications when team memberships change.
To configure the GitHub app and the webhook in the GitHub organisation settings:

- In **Code, planning, and automation** Webhooks, create a new webhook:
  - In **Payload URL**, input "https://<APP_DOMAIN>/github-webhook".
  - In **Content Type** choose **application/json**.
  - Generate a token and put in **Secret**. This token should be in `./credentials/GH_WEBHOOK_SECRET`.
  - Choose **Let me select individual events**
    - Deselect **Pushes**.
    - Select **Memberships**.

</details>

## Running the service in a development environment

Start a development shell:

```console
nix-shell
```

Or set up [`nix-direnv`](https://github.com/nix-community/nix-direnv) on your system and run `direnv allow` to enter the development environment automatically when entering the project directory.

### Set up a local database

Currently only [PostgreSQL](https://www.postgresql.org/) is supported as a database.
You can set up a database on NixOS like this:

```nix
{ ... }:
{
  imports = [
    (import nix-security-tracker { }).dev-setup
  ];

  nix-security-tracker-dev-environment = {
    enable = true;
    # The user you run the backend application as, so that you can access the local database
    user = "myuser";
  };
}
```

### Start the service

The service is comprised of the Django server and workers for ingesting CVEs and derivations.
What needs to be run is defined in the [`Procfile`](../Procfile) managed by [hivemind](https://github.com/DarthSim/hivemind).

Run everything with:

```bash
hivemind
```

### Resetting the database

In order to start over, delete the database and recreate it, then restore it from a dump, and (just in case the dump is behind the code) run migrations:

```bash
dropdb nix-security-tracker
sudo -u postgres createdb -O nix-security-tracker nix-security-tracker
pg_restore -O -d nix-security-tracker -v < dump
manage migrate
```

If you have SSH access to the staging environment, you can instead dump and restore the latest state directly:

```bash
ssh sectracker.nixpkgs.lahfa.xyz "sudo -u postgres pg_dump --create web-security-tracker | zstd" | zstdcat | sed 's|web-security-tracker|nix-security-tracker|g' | pv | psql
```

## Running the service in a container

On NixOS, you can run the service in a [`systemd-nspawn` container](https://search.nixos.org/options?show=containers) to preview a deployment.

Assuming you have a local checkout of this repository at `~/src/nix-security-tracker`, in your NixOS configuration, add the following entry to `imports` and rebuild your system:

```nix
{ ... }:
{
  imports = [
    (import ~/src/nix-security-tracker { }).dev-container
    # ...
   ];
}
```

The service will be accessible at <http://172.31.100.1>.

### Using a database dump

To upload a pre-existing database dump into the container with [`nixos-container`](https://nixos.org/manual/nixos/unstable/#sec-imperative-containers):

0. Get the most recent database dump:

   ```bash
   curl https://dumps.sectracker.nixpkgs.lahfa.xyz/web-security-tracker --output dump
   ```

1. Stop the server, delete the initial database, and create an empty one.

   ```bash
   sudo nixos-container run nix-security-tracker -- bash << EOF
   systemctl stop web-security-tracker-server.service
   systemctl stop web-security-tracker-worker.service
   sudo -u postgres dropdb web-security-tracker
   sudo -u postgres createdb web-security-tracker
   EOF
   ```

2. Restore the dump.

   ```bash
   sudo nixos-container run nix-security-tracker -- sudo -u postgres pg_restore -d web-security-tracker -v < dump
   ```

3. Start the service again.

   ```bash
   sudo nixos-container run nix-security-tracker -- bash << EOF
   systemctl start web-security-tracker-server.service
   systemctl start web-security-tracker-worker.service
   EOF
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

## Manual ingestion

### CVEs

Add 100 CVE entries to the database:

```console
manage ingest_bulk_cve --subset 100
```

This will take a few minutes on an average machine.
Not passing `--subset N` will take about an hour and produce ~500 MB of data.

## Staging deployment

If you have your SSH keys set up on the staging environment (and can connect through IPv6), you can deploy the service with:

```console
./infra/deploy.sh
```

### Adding SSH keys

Add your SSH keys to `./infra/configuration.nix` and let existing owners deploy them.

## Operators guidance

### Using a Sentry-like collector

Sentry-like collectors are endpoints where we ship error information from the Python application with its stack-local variables for all the traceback, you can use [Sentry](https://sentry.io/welcome/) or [GlitchTip](https://glitchtip.com/) as a collector.

Collectors are configured using [a DSN, i.e. a data source name.](https://docs.sentry.io/concepts/key-terms/dsn-explainer/) in Sentry parlance, this is where events are sent to.

You can set `GLITCHTIP_DSN` as a credential secret with a DSN and this will connect to a Sentry-like endpoint via your DSN.
