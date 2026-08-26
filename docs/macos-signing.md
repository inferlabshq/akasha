# macOS: sign local builds with a stable identity

If you build akasha from source (`go build` / `go install`) **and** run the
daemon on macOS, you have to sign the binary — otherwise the daemon will not
start at all. Use a **stable code-signing identity** rather than ad-hoc.

`install.sh` already does this for you. This note is for the `go build` /
`go install` workflow, where you sign the binary yourself.

## Why

Signing is what lets the daemon **run**. It is not what protects your vault key —
see the next section, because an earlier version of this note said otherwise.

- **launchd refuses to run an unsigned binary** (`OS_REASON_CODESIGNING`), and on
  Apple Silicon an unsigned Mach-O is killed by the OS before `main` — no output,
  exit 137. A locally built akasha must be signed with *something*.
- **A stable identity** (a self-signed code-signing cert reused across builds)
  gives every rebuild the same Designated Requirement —
  `identifier "dev.akasha.daemon" and certificate leaf = …` — instead of a fresh
  CDHash. Ad-hoc signing (`codesign -s -`) makes each build a different app to
  anything that pins akasha's identity, including launchd's own bookkeeping and
  any firewall or MDM rule you have.

Official release binaries get this from a **Developer ID** signature (stable
Team-ID DR) plus notarization — see
[`.github/workflows/release.yml`](../.github/workflows/release.yml). Locally,
a self-signed cert gives you the same stability.

## What signing does *not* do: gate access to your vault key

This note used to say the keychain ACL guarding the vault key is bound to
akasha's code signature, so replacing or re-signing the binary breaks access.
**That is not how it works here.** Akasha reaches the keychain through
`go-keyring`, whose darwin backend shells out to `/usr/bin/security` instead of
calling the Keychain API in-process:

```go
const execPathKeychain = "/usr/bin/security"   // keyring_darwin.go
```

So the item's ACL is written for `/usr/bin/security` — an Apple-signed system
binary — and akasha's own signature never enters the check. Confirmed with four
differently-signed akasha binaries (stable identity, ad-hoc, a fresh
cross-build, and one signed `-i com.example.totally-different`): all four read
the key from a real vault, with no prompt and no delay.

Two things follow, and both matter more than the signature does:

- **Re-signing or replacing the binary does not lock you out of your vault.** If
  `akasha start` reports "vault is locked" after an update, the signature is not
  the cause. Look at the login keychain instead: is it locked, are you in a
  different login session, is `HOME` pointing somewhere else (which drops the
  login keychain out of the search list entirely)? The command's own error text
  lists these.
- **Any process running as you can read the vault key** with one `security`
  command, signed or not. That is the real boundary; see
  [`THREATMODEL.md`](THREATMODEL.md#known-limitations-alpha--being-hardened).

Sign anyway — the daemon has to start.

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

## The safety net

Keep a key backup. Not because signing endangers it — it does not — but because
the vault key lives in exactly one keychain item, and anything that removes or
orphans that item (a purge interrupted halfway, a migrated machine, a keychain
reset) takes the vault with it:

```bash
akasha vault backup ~/akasha-key.backup
```

`akasha vault restore <file>` puts the key back in the keychain. It is the
recovery for a **lost or deleted** key, not for a signing change — a signing
change does not take your access away.

If `akasha start` says "vault is locked", read its error before restoring
anything: on macOS the usual causes are a locked login keychain or a `HOME` that
points somewhere other than your real home, and in both cases the key is still
sitting there intact.
