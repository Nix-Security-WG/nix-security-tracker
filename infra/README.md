# Nixpkgs Security Tracker infrastructure

This directory contains the infrastructure configuration for the Nixpkgs Security Tracker.
This includes both the NixOS configuration as well as the Terraform/OpenTofu files to spin up the resources.

## Hetzner Cloud

The infrastructure currently resides in [Hetzner Cloud](https://www.hetzner.com/cloud/), under the `nixpkgs-security-tracker` project.
To request access to the project on Hetzner Cloud, contact the [NixOS infrastructure team](https://nixos.org/community/teams/infrastructure/).
Besides the infrastructure team, @erethon also has access, but can't add users to the project.

## Terraform/OpenTofu

OpenTofu is used to spin up the VM infrastructure.
Its state is stored in Hetzner's Object Storage service.

Running `nix shell` in this directory will drop you in a shell with OpenTofu available.
To quickly get information on the committed state run `tofu show`.
For more instructions on how to use OpenTofu refer to the [upstream documentation](https://opentofu.org/docs/).

## NixOS hosts

Since Hetzner Cloud doesn't support NixOS out of the box, the VM was initially spawned as a Debian host and then it was converted to NixOS as per the [provisioning NixOS via SSH tutorial](https://nix.dev/tutorials/nixos/provisioning-remote-machines).
If in the future we need to create more VMs and do it in a declarative way, we can use [nixos-anywhere](https://github.com/nix-community/nixos-anywhere).

## Secrets

Secrets are managed using [Agenix](https://github.com/ryantm/agenix).
Agenix decrypts secrets on the host by using its [OpenSSH host keys](https://github.com/ryantm/agenix#ageidentitypaths).
Reading the [Agenix tutorial](https://github.com/ryantm/agenix#tutorial) is recommended.

### Managing secrets

To add or edit a secret, you don't need to have access to the private keys.
You only have to make sure that the file for the secret you want to edit doesn't exist, (i.e. delete `secrets/name_of_secret.age` if it already exists) and then run `agenix -e secrets/name_of_secret.age` from the directory that `secrets.nix` is in.
Then commit `secrets/name_of_secret.age` as usual.
