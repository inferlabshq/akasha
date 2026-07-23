#!/usr/bin/env bash
#
# Sign the shipped provider bundle with the official publisher key, so the
# daemon auto-trusts it (no per-user approval). Run once after provisioning the
# official key, and again whenever a bundled template changes.
#
#   scripts/sign-bundle.sh official.key
#
# Then commit daemon/internal/publisher/official.pub and daemon/templates/*.yaml.sig.
set -euo pipefail

key="${1:?usage: scripts/sign-bundle.sh <official-private-key-file>}"
akasha="${AKASHA_BIN:-akasha}"
command -v "$akasha" >/dev/null 2>&1 || { echo "akasha binary not found (set AKASHA_BIN)"; exit 1; }

count=0
for f in daemon/templates/*.yaml; do
  "$akasha" template sign "$f" --key "$key" --publisher akasha-official
  count=$((count + 1))
done
echo "Signed $count templates. Commit the *.yaml.sig files (and official.pub)."
