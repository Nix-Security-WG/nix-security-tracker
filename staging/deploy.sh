#!/usr/bin/env bash

set -eo pipefail

DIR=$(dirname $DIRENV_FILE)
VERB=${1:-switch}

# Perform a dry-activation first.
echo "dry-activating the configuration first..."
nixos-rebuild dry-activate -I nixos-config=$DIR/staging/configuration.nix --target-host root@sectracker.nixpkgs.lahfa.xyz

# This requires IPv6 to work as SSH is only IPv6-only.
# Sorry, not sorry.
echo "$VERB-ing the configuration now."
nixos-rebuild $VERB -I nixos-config=$DIR/staging/configuration.nix --target-host root@sectracker.nixpkgs.lahfa.xyz
