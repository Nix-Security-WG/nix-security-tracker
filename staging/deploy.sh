#!/usr/bin/env nix-shell
#!nix-shell -i bash -p nixos-rebuild

set -eo pipefail

DIR=$(git rev-parse --show-toplevel)
VERB=${1:-switch}

if [[ "$VERB" != "build" ]]; then
  # Perform a dry-activation first.
  echo "dry-activating the configuration first..."
  nixos-rebuild dry-activate -I nixos-config=$DIR/staging/configuration.nix --target-host root@sectracker.nixpkgs.lahfa.xyz
else
  echo "skipping the dry-activation as we are using an offline verb."
fi

# This requires IPv6 to work as SSH is only IPv6-only.
# Sorry, not sorry.
echo "$VERB-ing the configuration now."
nixos-rebuild $VERB -I nixos-config=$DIR/staging/configuration.nix --target-host root@sectracker.nixpkgs.lahfa.xyz
