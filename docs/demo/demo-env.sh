#!/usr/bin/env bash
#
# Prepare an isolated environment for recording docs/demo/demo.tape.
#
# Everything lives under /tmp/akdemo with synthetic credentials. The real
# ~/.akasha, the real vault and the real OS-keychain entry are never touched:
# the demo binary is built with a `.test` suffix so vault.go's isTestBinary()
# redirects the keychain service away from "akasha-daemon". Without that, a
# second vault on the same machine would either be refused by the re-key guard
# or — with AKASHA_ALLOW_NEW_VAULT=1 — REPLACE the real key and make the real
# vault permanently undecryptable.
#
#   ./docs/demo/demo-env.sh && vhs docs/demo/demo.tape
#
set -euo pipefail

D=/tmp/akdemo
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

pkill -f "$D/bin/akasha.test start" 2>/dev/null || true
sleep 1
rm -rf "$D"
mkdir -p "$D/home/.akasha/templates.dist" "$D/home/.ssh" "$D/bin"

# The recorded prompt types `akasha`; the wrapper execs the .test binary so the
# process keeps a .test argv[0] and stays on the isolated keychain service.
( cd "$REPO/daemon" && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-X main.version=$(git -C "$REPO" describe --tags --always 2>/dev/null || echo dev)" \
    -o "$D/bin/akasha.test" ./cmd/akasha )
printf '#!/bin/sh\nexec %s/bin/akasha.test "$@"\n' "$D" > "$D/bin/akasha"
chmod +x "$D/bin/akasha"

cp "$REPO"/daemon/templates/*.yaml "$D/home/.akasha/templates.dist/"
cp "$REPO"/daemon/templates/*.yaml.sig "$D/home/.akasha/templates.dist/" 2>/dev/null || true

# Synthetic only. The token is obviously fake and the key is generated here and
# thrown away with /tmp/akdemo.
ssh-keygen -q -t ed25519 -N '' -f "$D/home/.ssh/demo_key" -C demo@example
printf 'https://demo:ghp_0000000000000000000000000000000000@github.com\n' > "$D/home/.git-credentials"
chmod 600 "$D/home/.git-credentials"

# A real gitconfig, so the demo can show that agent sessions inherit the human's
# identity rather than losing it.
printf '[user]\n\tname = Demo User\n\temail = demo@example.com\n' > "$D/home/.gitconfig"

HOME="$D/home" PATH="$D/bin:$PATH" \
  env -u AKASHA_AGENT_KEY -u AKASHA_AGENT_ID "$D/bin/akasha" start >"$D/daemon.log" 2>&1 &

for _ in $(seq 1 20); do
  grep -qi 'listening on unix' "$D/daemon.log" && break
  sleep 0.5
done
grep -qi 'listening on unix' "$D/daemon.log" || { echo "daemon failed to start:"; head -6 "$D/daemon.log"; exit 1; }

echo "demo env ready at $D — now run: vhs docs/demo/demo.tape"
