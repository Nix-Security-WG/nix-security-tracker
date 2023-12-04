#!/usr/bin/env bash

# This requires IPv6 to work as SSH is only IPv6-only.
# Sorry, not sorry.
nixos-rebuild test -I nixos-config=configuration.nix --target-host root@sectracker.nixpkgs.lahfa.xyz
