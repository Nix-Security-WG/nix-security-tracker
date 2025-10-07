# Contributing Guide

This document is for anyone wanting to contribute to the implementation of the security tracker.

## Overview

This file contains general contribution information, but the other directories in this repository have additional `README.md` files with more specific information relevant to their sibling files:

# Hacking

The service is implemented in Python using [Django](https://www.djangoproject.com/).

## Formatting

A formatter is run on each pull request and as a pre-push Git hook.

Run the formatter manually with:

```console
nix-shell --run format
```

## Setting up credentials

The service connects to GitHub on startup, in order to manage permissions according to GitHub team membership in the configured organisation.

<details><summary>Create a Django secret key</summary>

```console
python3 -c 'import secrets; print(secrets.token_hex(100))' > .credentials/SECRET_KEY
```

</details>

<details><summary>Set up GitHub authentication</summary>

1.  Create a new or select an existing GitHub organisation to associate with the Nixpkgs security tracker.

    We're using <https://github.com/Nix-Security-WG> for development.
    - In the **Settings** tab under **Personal access tokens**, ensure that personal access tokens are allowed.
    - In the **Teams** tab, ensure there are at two teams for mapping user permissions.
      They will correspond to [`nixpkgs-committers`](https://github.com/orgs/nixos/teams/nixpkgs-committers) and [`security`](https://github.com/orgs/nixos/teams/security).
    - In the **Repositories** tab, ensure there's a repository for posting issues.
      It will correspond to [`nixpkgs`](https://github.com/nixos/nixpkgs).
      In the **Settings** tab on that repository, in the **Features** section, ensure that _Issues_ are enabled.

2.  In the GitHub organisation settings configure the GitHub App

    We're using <https://github.com/apps/sectracker-testing> for local development and <https://github.com/apps/sectracker-demo> for the public demo deployment.
    [Register a new GitHub application](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) if needed.
    - In **Personal access tokens** approve the request under **Pending requests** if approval is required
    - In **GitHub Apps**, go to **Configure** and then **App settings** (top row). Under **Permissions & events** (side panel):
      - In **Repository Permissions** select **Administration (read-only)**, **Issues (read and write)**, and **(Metadata: read-only)**.
      - In **Organization Permissions** select **Administration (read-only)** and **(Members: read-only)**.

      Store the **Client ID** in `.credentials/GH_CLIENT_ID`

    - In the application settings / **General** / **Generate a new client secret**

      Store the value in `.credentials/GH_SECRET`

    - In the application settings / **General** / **Private keys** / **Generate a private key**

      Store the value in `.credentials/GH_APP_PRIVATE_KEY`

    - In the application settings / **Install App**

      Make sure the app is installed in the correct organisation's account.

      <details><summary>If the account that shows up is your Developer Account</summary>

      In the application settings / **Advanced**
      - **Transfer ownership of this GitHub App** to the organisation account.

      </details>

    - In organisation settings under **GitHub Apps** / **Installed GitHub Apps** / **<GH_APP_NAME>** / **Configure** page

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

### Caching suggestions and issues

Suggestion and issue contents are displayed from a cache to avoid latency from complex database queries.

To compute or re-compute the cached information from scratch:

```console
manage regenerate_cached_suggestions
manage regenerate_cached_issues
```

## Staging deployment

See [infra/README.md](infra/README.md#Deploying-the-Security-Tracker).

## Operators guidance

### Using a Sentry-like collector

Sentry-like collectors are endpoints where we ship error information from the Python application with its stack-local variables for all the traceback, you can use [Sentry](https://sentry.io/welcome/) or [GlitchTip](https://glitchtip.com/) as a collector.

Collectors are configured using [a DSN, i.e. a data source name.](https://docs.sentry.io/concepts/key-terms/dsn-explainer/) in Sentry parlance, this is where events are sent to.

You can set `GLITCHTIP_DSN` as a credential secret with a DSN and this will connect to a Sentry-like endpoint via your DSN.
