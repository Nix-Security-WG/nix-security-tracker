# Architecture

## High Level Overview

The Security tracker consists of a server process that's responsible for
handling HTTP requests and a worker process that's doing all the background
processing.

![Overall Architecture](./svg/architecture.svg)

### External services

The tracker needs to communicate with third party services, namely:

1) The GitHub API for user authentication, team permissions, creating issues, etc
2) Two GitHub repos:
   a) https://github.com/nixos/nixpkgs to pull the latest changes on nixpkgs
   b) https://github.com/CVEProject/cvelistV5 to pull CVE data
3) https://prometheus.nixos.org/ to get information about the latest channels


# Database Schema

![Database Schema](./svg/models.svg)

# Nix Store, storage space and filesystem considerations

The tracker requires significant storage space to run properly. In particular,
there are two different areas you'll need storage for, the database and the Nix
store.

## Database

In order to store three diffent Nixpkgs releases, you'll need around 80GB of
space for the Postgresql database. This is the case right now for storing
24.05, 24.11 and 25.05.

As the number of CVEs and packages increases, the storage space requirement
will most likely increase as well.

## Nix Store and filesystem

Since the tracker builds derivations for all packages, it creates a lot of
small files in the filesystem. You need to make sure you have both enough space
for this and enough inodes on your filesystem. We suggest you [optimise the nix
store](https://wiki.nixos.org/wiki/Storage_optimization) and turn on automatic
optimisation.

If you're using ext4, read this [Nix issue](https://github.com/NixOS/nix/issues/1522)
as you'll need to enable support for `large_dir`in your filesystem for
optimisation to work.
