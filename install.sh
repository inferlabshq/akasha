#!/usr/bin/env bash
#
# Akasha installer — downloads a verified prebuilt binary (preferred) or builds
# from source as a fallback, signs it on macOS, and installs to ~/.local/bin.
# Then run `akasha setup`.
#
#   curl -sSL https://getakasha.dev/install | sh
#
# Prebuilt binaries are static (CGO disabled) and published as GitHub release
# assets alongside a SHA256SUMS file; this script verifies the checksum before
# installing. Set AKASHA_BUILD_FROM_SOURCE=1 to skip the download and build.
#
# POSIX sh only: the documented install command pipes this script to `sh`, which
# is dash on Debian/Ubuntu. `set -o pipefail` is a fatal builtin error there and
# aborts the whole script, so no bashisms below either.
set -eu

INSTALL_DIR="${AKASHA_INSTALL_DIR:-$HOME/.local/bin}"
BIN="$INSTALL_DIR/akasha"
# During the private alpha, prebuilt binaries are hosted on the getakasha.dev
# CDN (the repo's GitHub Releases aren't public yet). Flip this back to the
# GitHub Releases URL once the repo is public. Override with AKASHA_RELEASE_BASE;
# the source-build fallback clones AKASHA_REPO_URL.
RELEASE_BASE="${AKASHA_RELEASE_BASE:-https://getakasha.dev/dl}"
REPO_URL="${AKASHA_REPO_URL:-https://github.com/inferlabshq/akasha.git}"
REPO_DIR="${AKASHA_REPO_DIR:-}"
# Provider templates are shipped as DATA (not compiled into the binary). The
# daemon loads this curated bundle from ShippedDir; AKASHA_SHIPPED_TEMPLATES_DIR
# must match the daemon default in internal/template/load.go.
SHIPPED_TEMPLATES_DIR="${AKASHA_SHIPPED_TEMPLATES_DIR:-$HOME/.akasha/templates.dist}"

say()  { printf '\033[1;36m›\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[1;31m✗\033[0m %s\n' "$1" >&2; exit 1; }

# A hash that failed to compute must never reach a comparison: an empty string
# compares unequal and would be reported as a checksum MISMATCH, sending the
# user after a tampered download that never happened.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then h="$(sha256sum "$1" | awk '{print $1}')"
  elif command -v shasum    >/dev/null 2>&1; then h="$(shasum -a 256 "$1" | awk '{print $1}')"
  else return 1; fi
  [ -n "$h" ] || return 1
  printf '%s\n' "$h"
}

# ── Detect platform ─────────────────────────────────────────────────────────
os="$(uname -s | tr '[:upper:]' '[:lower:]')"   # darwin | linux
case "$(uname -m)" in
  x86_64|amd64)   arch="amd64" ;;
  arm64|aarch64)  arch="arm64" ;;
  *)              arch="unsupported" ;;
esac
asset="akasha-${os}-${arch}"

mkdir -p "$INSTALL_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── Preferred: download a checksum-verified prebuilt binary ─────────────────
download_prebuilt() {
  [ "${AKASHA_BUILD_FROM_SOURCE:-0}" = "1" ] && return 1

  # Running from a checkout means you want YOUR code. Downloading the published
  # binary here is the most confusing thing this script can do: the install
  # succeeds, everything looks right, and your changes are simply not in the
  # binary — a trap that costs a debugging session before anyone suspects the
  # installer. Set AKASHA_FORCE_PREBUILT=1 to test the download path itself.
  if [ -d "daemon/cmd/akasha" ] && [ "${AKASHA_FORCE_PREBUILT:-0}" != "1" ]; then
    say "Detected an akasha checkout — building from source so you get your code."
    say "(set AKASHA_FORCE_PREBUILT=1 to download the published binary instead)"
    return 1
  fi
  [ "$arch" = "unsupported" ] && { warn "No prebuilt binary for $(uname -m)."; return 1; }
  command -v curl >/dev/null 2>&1 || return 1

  say "Downloading $asset (verified)..."
  curl -fsSL "$RELEASE_BASE/$asset"    -o "$TMP/akasha"     || { warn "No published binary for ${os}/${arch} yet."; return 1; }
  curl -fsSL "$RELEASE_BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || { warn "Could not fetch SHA256SUMS."; return 1; }

  want="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$TMP/SHA256SUMS")"
  [ -n "$want" ] || { warn "No checksum listed for $asset."; return 1; }
  got="$(sha256 "$TMP/akasha")" || die "Could not compute a SHA256 for $asset — refusing to install unverified.
  install sha256sum (coreutils) or shasum, or build from source:
    AKASHA_BUILD_FROM_SOURCE=1 sh install.sh"
  [ "$want" = "$got" ] || die "Checksum mismatch for $asset — refusing to install.
  expected $want
  got      $got"

  install -m 0755 "$TMP/akasha" "$BIN"
  ok "Verified SHA256 and installed prebuilt binary"

  # Templates ship as a separate, checksum-verified bundle.
  say "Downloading provider templates (verified)..."
  if curl -fsSL "$RELEASE_BASE/akasha-templates.tar.gz" -o "$TMP/templates.tar.gz"; then
    twant="$(awk '$2 == "akasha-templates.tar.gz" || $2 == "*akasha-templates.tar.gz" {print $1}' "$TMP/SHA256SUMS")"
    tgot="$(sha256 "$TMP/templates.tar.gz")" || die "Could not compute a SHA256 for the templates bundle — refusing to install unverified.
  install sha256sum (coreutils) or shasum, or build from source:
    AKASHA_BUILD_FROM_SOURCE=1 sh install.sh"
    [ -n "$twant" ] && [ "$twant" = "$tgot" ] || die "Checksum mismatch for templates bundle — refusing to install."
    install_templates_from_tar "$TMP/templates.tar.gz"
  else
    warn "No templates bundle published yet — the daemon will start with no providers until you add some."
  fi
  return 0
}

# install_templates_from_tar extracts the bundle (which contains a top-level
# templates/ dir) into ShippedDir.
install_templates_from_tar() {
  mkdir -p "$SHIPPED_TEMPLATES_DIR"
  tar -xzf "$1" -C "$TMP"
  cp "$TMP"/templates/*.yaml "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
  # Signatures (if the bundle was signed) confer hands-off trust on the daemon.
  cp "$TMP"/templates/*.yaml.sig "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
  ok "Installed provider templates to $SHIPPED_TEMPLATES_DIR"
}

# install_templates_from_source copies the curated bundle out of a checkout.
install_templates_from_source() {
  if [ -d "$REPO_DIR/daemon/templates" ]; then
    mkdir -p "$SHIPPED_TEMPLATES_DIR"
    cp "$REPO_DIR"/daemon/templates/*.yaml "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
    cp "$REPO_DIR"/daemon/templates/*.yaml.sig "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
    ok "Installed provider templates to $SHIPPED_TEMPLATES_DIR"
  fi
}

# ── Stable code-signing identity (macOS) ────────────────────────────────────
# Ad-hoc signatures (`codesign -s -`) have NO stable identity: the signature's
# Designated Requirement is the raw CDHash, so every rebuild is "a different app"
# to the keychain — and the ACL guarding the vault key breaks (re-prompt or
# lockout) on every update. A self-signed code-signing cert fixes this: its
# Designated Requirement is `identifier + this cert`, stable across rebuilds, so
# keychain access to the vault key persists. Official release binaries are
# Developer ID-signed + notarized (see .github/workflows/release.yml); this
# per-machine cert is the source / `go install` path. Force ad-hoc with
# AKASHA_ADHOC_SIGN=1.
SIGN_CN="Akasha Local Code Signing"
SIGN_ID="dev.akasha.daemon"

# NOTE: deliberately no -v. That flag filters to VALID identities, and a
# self-signed certificate is not "valid" — nothing vouches for it — so
# `find-identity -v` reports zero matches even immediately after a successful
# import. With -v this function could never return true, which meant
# ensure_signing_cert always reported failure and every install silently fell
# back to ad-hoc signing.
# A certificate with no private key still lists here, and cannot sign anything.
# That state is reachable — an interrupted import, or a key pruned from the
# keychain while its certificate stayed — and checking only for the certificate
# made it unrecoverable: ensure_signing_cert saw an identity, skipped creating
# one, signing then failed, and the fallback advice pointed at
# set-key-partition-list, which cannot help because there is no key to
# authorise. Requiring the key means the orphaned certificate is simply
# replaced on the next run.
have_signing_identity() {
  security find-identity -p codesigning 2>/dev/null | grep -qF "$SIGN_CN" || return 1
  # Only treat a missing key as disqualifying where find-key is supported;
  # elsewhere fall back to the certificate check rather than looping on create.
  if security find-key -h >/dev/null 2>&1 || [ $? -ne 127 ]; then
    security find-key -a -l "$SIGN_CN" >/dev/null 2>&1 || return 1
  fi
  return 0
}

# can_sign_with_identity checks that codesign can actually USE the key, with a
# timeout, because the failure mode is a hang rather than an error.
#
# Importing with `-T /usr/bin/codesign` adds codesign to the key's ACL but does
# NOT update the key's partition list, which macOS has also required since
# Sierra. When the partition list does not authorise it, codesign blocks on a
# GUI dialog ("codesign wants to use a key…") — indefinitely, and invisibly if
# the install is running non-interactively or over SSH. Signing a throwaway file
# under a timeout tells us which world we are in before we touch the real binary.
can_sign_with_identity() {
  local probe="$TMP/signprobe" limit=10
  cp "$BIN" "$probe" 2>/dev/null || cp /usr/bin/true "$probe" 2>/dev/null || return 1

  # When someone is watching, the dialog is answerable — so say it is coming and
  # wait long enough for a human to react. A 10s timeout would fall back to
  # ad-hoc while the user was still reading the prompt, which is the one
  # outcome worse than not offering the stable identity at all: they clicked
  # "Always Allow" and got ad-hoc anyway.
  if [ -t 0 ] || [ -t 2 ]; then
    limit=90
    say "macOS may now ask whether codesign can use the new signing key."
    say 'Click "Always Allow" — this is a one-time authorisation.'
  fi

  codesign -s "$SIGN_CN" -f --identifier "$SIGN_ID" "$probe" >/dev/null 2>&1 &
  local pid=$! i=0
  while [ $i -lt $limit ]; do
    kill -0 "$pid" 2>/dev/null || { wait "$pid"; return $?; }
    sleep 1; i=$((i+1))
  done
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 1
}

# ensure_signing_cert creates a per-machine self-signed code-signing certificate
# in the login keychain if one isn't already present. One-time; on first sign
# macOS may show a dialog to let codesign use the new key — click "Always Allow".
ensure_signing_cert() {
  have_signing_identity && return 0
  command -v openssl  >/dev/null 2>&1 || return 1
  command -v security >/dev/null 2>&1 || return 1

  # Prefer the SYSTEM openssl over whatever is first on PATH.
  #
  # macOS ships LibreSSL, which writes a bundle Security can read. A Homebrew
  # OpenSSL 3 shadows it on most developer machines, and -legacy alone is not
  # enough there: on 3.6 the import silently takes the CERTIFICATE and drops the
  # PRIVATE KEY. The result looks like success — an identity appears in
  # find-identity — but nothing can sign with it, and set-key-partition-list
  # cannot fix it because there is no key to authorise. Reaching for the
  # known-good implementation avoids the whole compatibility question.
  local ossl="openssl"
  [ -x /usr/bin/openssl ] && ossl=/usr/bin/openssl

  say "Creating a one-time local code-signing certificate (keeps the vault-key keychain ACL stable across updates)..."
  local d="$TMP/signcert"; mkdir -p "$d"
  cat > "$d/req.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $SIGN_CN
[ext]
basicConstraints = critical,CA:FALSE
extendedKeyUsage = codeSigning
EOF
  "$ossl" req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$d/key.pem" -out "$d/cert.pem" -config "$d/req.cnf" >/dev/null 2>&1 || return 1
  # -legacy is load-bearing. OpenSSL 3 defaults to a SHA-256 PKCS#12 MAC and
  # AES-256-CBC encryption, neither of which macOS's Security framework can
  # read; `security import` fails with "MAC verification failed during PKCS12
  # import (wrong password?)", which sends you looking at the password for a
  # problem that is entirely about the algorithm. LibreSSL (the system openssl)
  # and OpenSSL 1.x produce a compatible file already and reject -legacy as an
  # unknown flag, so fall through to naming the old algorithms explicitly.
  "$ossl" pkcs12 -export -legacy -inkey "$d/key.pem" -in "$d/cert.pem" \
      -name "$SIGN_CN" -out "$d/id.p12" -passout pass:akasha >/dev/null 2>&1 \
    || "$ossl" pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 \
      -inkey "$d/key.pem" -in "$d/cert.pem" \
      -name "$SIGN_CN" -out "$d/id.p12" -passout pass:akasha >/dev/null 2>&1 \
    || return 1

  # -k names the login keychain explicitly. Without it the destination is
  # whatever the default happens to be, and the observed failure is partial
  # rather than loud: the CERTIFICATE lands, the PRIVATE KEY does not, and
  # find-identity then reports an identity that cannot sign a thing. The error
  # surfaces much later as "The specified item could not be found in the
  # keychain" from codesign, which reads like the certificate is missing when it
  # is sitting right there.
  security import "$d/id.p12" -k "$HOME/Library/Keychains/login.keychain-db" \
    -P akasha -T /usr/bin/codesign >"$d/import.log" 2>&1 || {
    warn "could not import the signing identity: $(head -1 "$d/import.log")"
    return 1
  }

  # Authorise codesign to use the key without a prompt. This needs the login
  # keychain password, so it is best-effort: an empty password succeeds only on
  # a keychain that has one. When it does not work the first codesign shows a
  # dialog, which can_sign_with_identity detects rather than hanging on.
  security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || true

  have_signing_identity
}

# preflight_backup_notice warns before an existing binary is replaced: changing
# the signing identity (notably the one-time upgrade from ad-hoc to the cert
# above) re-prompts for vault-key keychain access, and a key backup is the
# recovery net if that goes wrong. `akasha vault backup` needs your passphrase
# so we can't run it here — we recommend it. Silence with AKASHA_SKIP_BACKUP=1.
preflight_backup_notice() {
  [ "$os" = "darwin" ] || return 0
  [ -e "$BIN" ] || return 0                     # fresh install → nothing to lose
  [ -f "$HOME/.akasha/vault.db" ] || return 0   # no existing vault → nothing to lose
  [ "${AKASHA_SKIP_BACKUP:-0}" = "1" ] && return 0
  warn "An existing akasha vault was found. Replacing the binary can change its"
  warn "code signature; if the signing identity changes, macOS re-prompts for"
  warn "keychain access to your vault key. Back it up first (recovery net):"
  printf '      akasha vault backup ~/akasha-key.backup\n' >&2
  printf '    (already backed up, or a fresh machine? set AKASHA_SKIP_BACKUP=1)\n' >&2
  if [ -t 0 ]; then
    printf '    Press Return to continue, or Ctrl-C to abort... ' >&2
    read -r _ || true
  fi
}

# ── Fallback: build from source (requires Go) ───────────────────────────────
build_from_source() {
  warn "Falling back to building from source — this needs Go 1.25+."
  if [ -z "$REPO_DIR" ]; then
    if [ -d "daemon/cmd/akasha" ]; then
      REPO_DIR="$(pwd)"
    elif command -v git >/dev/null 2>&1; then
      REPO_DIR="$TMP/akasha-src"
      say "Cloning akasha..."
      git clone --depth 1 "$REPO_URL" "$REPO_DIR" >/dev/null 2>&1 || die "git clone failed"
    else
      die "Run from an akasha checkout, or install git + Go first."
    fi
  fi
  command -v go >/dev/null 2>&1 || die "Go 1.25+ is required (https://go.dev/dl/)"
  say "Building daemon..."
  # Stamp the version so the installed binary can identify itself. Without it
  # a user told to "upgrade past the bypass in alpha.2" has no way to confirm
  # they did.
  _ver="$( (cd "$REPO_DIR" && git describe --tags --always --dirty 2>/dev/null) || echo dev )"
  ( cd "$REPO_DIR/daemon" && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=$_ver" -o "$TMP/akasha" ./cmd/akasha ) \
    || die "build failed"
  install -m 0755 "$TMP/akasha" "$BIN"
  ok "Built from source and installed"
  install_templates_from_source
}

preflight_backup_notice
download_prebuilt || build_from_source

# ── Code-sign on macOS ──────────────────────────────────────────────────────
# launchd refuses to run an unsigned binary (OS_REASON_CODESIGNING). We sign
# with a STABLE identity (see ensure_signing_cert) so replacing the binary does
# NOT break the keychain ACL guarding the vault key — the whole point. Ad-hoc is
# the graceful fallback, but it re-prompts for keychain access on every update.
sign_adhoc() {
  codesign -s - -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
    && { ok "Code-signed (ad-hoc)"
         warn "Ad-hoc signing: updating akasha may re-prompt for vault-key keychain access."; } \
    || warn "codesign failed — daemon may not start under launchd"
}

if [ "$os" = "darwin" ] && command -v codesign >/dev/null 2>&1; then
  if [ "${AKASHA_ADHOC_SIGN:-0}" = "1" ]; then
    sign_adhoc
  elif ensure_signing_cert && can_sign_with_identity; then
    codesign -s "$SIGN_CN" -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
      && ok "Code-signed with stable local identity — keychain access persists across updates" \
      || { warn "Stable-identity signing failed; falling back to ad-hoc."; sign_adhoc; }
  else
    # Reached when the identity is missing, OR when it exists but macOS will not
    # let codesign use the key without a GUI prompt. The second case used to
    # hang the install indefinitely; can_sign_with_identity turns it into this
    # message. Explain the one-time fix rather than leaving the user to discover
    # that every update churns their keychain.
    if have_signing_identity; then
      warn "A local signing identity exists, but macOS will not let codesign use its key"
      warn "without asking. Authorise it once, then re-run this installer:"
      printf '\n      security set-key-partition-list -S apple-tool:,apple:,codesign: -s ~/Library/Keychains/login.keychain-db\n\n' >&2
      # Deliberately WITHOUT -k: omitting it makes security prompt for the
      # keychain password, so the password never lands in argv (visible to any
      # process via ps) or in shell history. Suggesting `-k <password>` on a
      # tool whose entire job is keeping secrets out of process environments
      # would be a poor example to set.
      printf '    It will prompt for your login password.\n' >&2
      printf '    (or run this installer from a graphical session and click "Always Allow")\n' >&2
    fi
    sign_adhoc
  fi
fi

ok "Installed: $BIN"

# ── PATH hint ───────────────────────────────────────────────────────────────
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "Add $INSTALL_DIR to your PATH:"
     printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc\n' "$INSTALL_DIR" ;;
esac

printf '\n'
ok "Akasha installed. Next:"
printf '    akasha setup\n\n'
