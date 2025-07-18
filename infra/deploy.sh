#!/usr/bin/env nix-shell
#!nix-shell -i bash -p nixos-rebuild coreutils

set -eo pipefail

DIR=$(git rev-parse --show-toplevel)
VERB=${1:-switch}
HOST=${2:-staging-tracker.security.nixos.org}  # Default to staging
# make sure we're building with the version of Nixpkgs under our control
export NIX_PATH=nixpkgs=$(nix-instantiate --eval -A pkgs.path)

# Note: we could refactor the conditional here.
# But `nixos-rebuild build --target-host ...` requiring network operations is an unexpected bug.
# Therefore, we keep the two conditionals separated for the day when we will
# replace `nixos-rebuild` by a tool that does not have this bug but similar
# semantics.
# Example: `colmena apply dry-activate` then `colmena build` does have these
# properties and would make the second conditional disappear.

if [[ "$VERB" != "build" ]]; then
  # Perform a dry-activation first.
  echo "dry-activating the configuration first..."
  nixos-rebuild dry-activate -I nixos-config=$DIR/infra/configuration.nix --target-host root@$HOST
else
  echo "skipping the dry-activation as we are using an offline verb."
fi


if [[ "$VERB" != "build" ]]; then
  echo "$VERB-ing the configuration now."
  nixos-rebuild $VERB -I nixos-config=$DIR/infra/configuration.nix --target-host root@$HOST
else
  echo "building the configuration now."
  nixos-rebuild build -I nixos-config=$DIR/infra/configuration.nix
fi
