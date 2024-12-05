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
