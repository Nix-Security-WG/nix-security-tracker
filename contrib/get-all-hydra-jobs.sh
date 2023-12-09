#!/usr/bin/env bash
NIXPKGS_ALLOW_INSECURE=1 nix-eval-jobs --force-recurse --meta --repair --quiet --gc-roots-dir /tmp/gcroots --expr "(import <nixpkgs/pkgs/top-level/release.nix> { })" --include nixpkgs=$LOCAL_NIXPKGS_CHECKOUT "$@" > evaluation.jsonl
