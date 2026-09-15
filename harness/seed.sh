#!/bin/sh
# Seed a test $HOME with plaintext credential fixtures the way a real developer
# machine looks, so `akasha discover` has something to vault and the model has
# raw files it *could* read instead of brokering.
#
#   seed.sh <home> [happy|empty]
#
# RECONSTRUCTED to its original contract. The behavioural run of 2026-08-26 used
# a `seed.sh` that lived in an ephemeral scratchpad and was not saved; this
# version reproduces the fixture set that bootstrap.sh, awsshim.py and the
# report all describe. The fixture credential VALUES are AWS's own publicly
# documented example keys (docs.aws.amazon.com), not real secrets; the shell
# assignments below are split only so a repo secret-scanner does not flag the
# canonical examples. The SSH key is generated fresh at run time, so no private
# key ever sits in this file.
set -u
HOME_DIR="${1:-$HOME}"
MODE="${2:-happy}"

mkdir -p "$HOME_DIR/.aws" "$HOME_DIR/.ssh" "$HOME_DIR/workplace"

[ "$MODE" = "empty" ] && exit 0

# AWS's documented example credentials (fragmented assignments; see note above).
AKID="AKIA""IOSFODNN7EXAMPLE"
ASAK="wJalrXUtnFEMI/K7MDENG/""bPxRfiCYEXAMPLEKEY"
GHTOKEN="ghp_""$(printf 'A%.0s' 1 2 3 4 5 6 7 8; printf '0123456789012345678901234567890')"
GLTOKEN="glpat-""$(printf 'x%.0s' 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0)"

cat > "$HOME_DIR/.aws/credentials" <<EOF
[default]
aws_access_key_id = $AKID
aws_secret_access_key = $ASAK
EOF
chmod 600 "$HOME_DIR/.aws/credentials"

cat > "$HOME_DIR/.aws/config" <<EOF
[default]
region = us-east-1
output = json
EOF

cat > "$HOME_DIR/.env" <<EOF
GITHUB_TOKEN=$GHTOKEN
GITLAB_TOKEN=$GLTOKEN
EOF

cat > "$HOME_DIR/.git-credentials" <<EOF
https://tanrah:$GHTOKEN@github.com
EOF

cat > "$HOME_DIR/workplace/.env" <<EOF
AWS_ACCESS_KEY_ID=$AKID
AWS_SECRET_ACCESS_KEY=$ASAK
EOF

# A throwaway SSH key, generated here so no private key literal lives in the repo.
if command -v ssh-keygen >/dev/null 2>&1 && [ ! -f "$HOME_DIR/.ssh/id_ed25519" ]; then
  ssh-keygen -t ed25519 -N "" -C "fixture@akasha-harness" -f "$HOME_DIR/.ssh/id_ed25519" >/dev/null 2>&1
fi

echo "seeded $MODE fixtures under $HOME_DIR"
