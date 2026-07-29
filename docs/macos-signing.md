# macOS: sign local builds with a stable identity

If you build akasha from source (`go build` / `go install`) **and** run the
daemon on macOS, sign the binary with a **stable code-signing identity**. This
is not cosmetic — it's what keeps your vault readable across rebuilds.

`install.sh` already does this for you. This note is for the `go build` /
`go install` workflow, where you sign the binary yourself.

## Why (the keychain-ACL trap)

Your vault's encryption key lives in the OS keychain. A keychain item's access
is governed by an ACL bound to the accessing binary's **Designated Requirement
(DR)** — not its file path.

- **Ad-hoc signing** (`codesign -s -`, the tempting default) produces a DR that
  is just the binary's **CDHash** — a hash of its bytes. Every rebuild changes
  the bytes, so every rebuild is "a different app" to the keychain. The ACL no
  longer matches → macOS re-prompts, and if the daemon can't get the key it
  **hangs** on the (possibly unseen) dialog. Decrypt paths stall while
  `akasha status` still works, because status only counts rows.
- **A stable identity** (a self-signed code-signing cert, reused across builds)
  produces a DR like `identifier "dev.akasha.daemon" and certificate leaf = …`,
  which matches *every* future build signed with the same cert. The ACL, once
  approved, keeps working. No re-prompts, no lockouts.

Official release binaries get this from a **Developer ID** signature (stable
Team-ID DR) plus notarization — see
[`.github/workflows/release.yml`](../.github/workflows/release.yml). Locally,
a self-signed cert gives you the same stability.

## Easiest path: use `install.sh`

```bash
./install.sh
```

It creates a per-machine `Akasha Local Code Signing` cert on first run and signs
every install with it. If you go this route, you can stop reading.

## Manual path (for `go build` / `go install` iteration)

### 1. One-time: create the signing cert

Creates a self-signed **code-signing** certificate in your login keychain. Run
once per machine.

```bash
d=$(mktemp -d)
cat > "$d/req.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = Akasha Local Code Signing
[ext]
basicConstraints = critical,CA:FALSE
extendedKeyUsage = codeSigning
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$d/key.pem" -out "$d/cert.pem" -config "$d/req.cnf"
openssl pkcs12 -export -inkey "$d/key.pem" -in "$d/cert.pem" \
  -name "Akasha Local Code Signing" -out "$d/id.p12" -passout pass:akasha
security import "$d/id.p12" -P akasha -T /usr/bin/codesign
rm -rf "$d"
```

Verify it's usable:

```bash
security find-identity -v -p codesigning | grep "Akasha Local Code Signing"
```

The `-config` file form (not `-addext`) is used so this works on stock macOS
LibreSSL as well as OpenSSL.

### 2. Every build: sign in place with the cert

Sign **at the install path**, after the binary is in place — not a copy signed
elsewhere. `-i dev.akasha.daemon` sets the stable identifier that anchors the DR
(and matches the launchd label).

```bash
cd daemon
go build -trimpath -ldflags "-s -w" -o "$HOME/.local/bin/akasha" ./cmd/akasha
codesign -s "Akasha Local Code Signing" -i dev.akasha.daemon -f "$HOME/.local/bin/akasha"
codesign -v "$HOME/.local/bin/akasha"   # sanity check
```

launchd refuses to run an **unsigned** binary (`OS_REASON_CODESIGNING`), so this
step is also what lets the daemon start at all under `launchctl`.

### 3. Restart the daemon to pick up the new binary

```bash
launchctl bootout   gui/$(id -u)/dev.akasha.daemon
# wait ~10s — launchd throttles fast respawns, or bootstrap fails with I/O error
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.akasha.daemon.plist
akasha status   # vault_total should be your entry count, not 0
```

## The one-time transition, and the safety net

The **first** time you switch an existing install from ad-hoc to the cert (or
change the cert), the identity changes once, so macOS re-prompts for keychain
access — click **Always Allow**. Every build after that is stable.

Before replacing a binary that guards a real vault, back up the key so a botched
transition is recoverable:

```bash
akasha vault backup ~/akasha-key.backup
```

If a decrypt path ever hangs or returns "vault is locked" after a signing
change, the recovery is:

```bash
akasha vault restore ~/akasha-key.backup   # re-establishes keychain access
```

Your encrypted data is never lost by a signing change — only *access* to the key
is; `vault restore` re-grants it to the current binary.
