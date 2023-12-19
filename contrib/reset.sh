#!/bin/sh

# Quickly reset the database to a known-good state

set -e

DIR=$(dirname $DIRENV_FILE)

if [ ! -f "$DIR/contrib/evaluation.jsonl" ]; then
    cat << EOF
Evaluation file is missing:

    $DIR/contrib/evaluation.jsonl

Run an evaluation (>30 min):

    $DIR/contrib/get-all-hydra-jobs.sh -I nixpkgs=channel:nixos-23.11
    mv evaluation.jsonl $DIR/contrib/evaluation.jsonl

Or get a pre-made evaluation:

    wget https://files.lahfa.xyz/private/evaluation.jsonl.zst
    zstd -d evaluation.jsonl.zst -o ./contrib/evaluation.jsonl
EOF
    exit 1
fi

dropdb nix-security-tracker
createdb nix-security-tracker
manage migrate
manage createsuperuser --username admin  # prompts for password
manage ingest_bulk_cve --subset 100
manage fetch_all_channels
manage ingest_manual_evaluation cd17fb8b3bfd63bf4a54512cfdd987887e1f15eb nixos-unstable $DIR/contrib/evaluation.jsonl --subset 100
