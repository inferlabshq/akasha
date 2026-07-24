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
set -euo pipefail

INSTALL_DIR="${AKASHA_INSTALL_DIR:-$HOME/.local/bin}"
BIN="$INSTALL_DIR/akasha"
# Public distribution is GitHub releases. Override with AKASHA_RELEASE_BASE /
# AKASHA_REPO_URL (the internal GitLab mirror sets these).
RELEASE_BASE="${AKASHA_RELEASE_BASE:-https://github.com/inferlabshq/akasha/releases/latest/download}"
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

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else return 1; fi
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
  [ "$arch" = "unsupported" ] && { warn "No prebuilt binary for $(uname -m)."; return 1; }
  command -v curl >/dev/null 2>&1 || return 1

  say "Downloading $asset (verified)..."
  curl -fsSL "$RELEASE_BASE/$asset"    -o "$TMP/akasha"     || { warn "No published binary for ${os}/${arch} yet."; return 1; }
  curl -fsSL "$RELEASE_BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || { warn "Could not fetch SHA256SUMS."; return 1; }

  want="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$TMP/SHA256SUMS")"
  [ -n "$want" ] || { warn "No checksum listed for $asset."; return 1; }
  got="$(sha256 "$TMP/akasha")" || die "No sha256 tool (sha256sum/shasum) to verify the download."
  [ "$want" = "$got" ] || die "Checksum mismatch for $asset — refusing to install.
  expected $want
  got      $got"

  install -m 0755 "$TMP/akasha" "$BIN"
  ok "Verified SHA256 and installed prebuilt binary"

  # Templates ship as a separate, checksum-verified bundle.
  say "Downloading provider templates (verified)..."
  if curl -fsSL "$RELEASE_BASE/akasha-templates.tar.gz" -o "$TMP/templates.tar.gz"; then
    twant="$(awk '$2 == "akasha-templates.tar.gz" || $2 == "*akasha-templates.tar.gz" {print $1}' "$TMP/SHA256SUMS")"
    tgot="$(sha256 "$TMP/templates.tar.gz")" || die "No sha256 tool to verify templates."
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

have_signing_identity() {
  security find-identity -v -p codesigning 2>/dev/null | grep -qF "$SIGN_CN"
}

# ensure_signing_cert creates a per-machine self-signed code-signing certificate
# in the login keychain if one isn't already present. One-time; on first sign
# macOS may show a dialog to let codesign use the new key — click "Always Allow".
ensure_signing_cert() {
  have_signing_identity && return 0
  command -v openssl  >/dev/null 2>&1 || return 1
  command -v security >/dev/null 2>&1 || return 1
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
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$d/key.pem" -out "$d/cert.pem" -config "$d/req.cnf" >/dev/null 2>&1 || return 1
  openssl pkcs12 -export -inkey "$d/key.pem" -in "$d/cert.pem" \
    -name "$SIGN_CN" -out "$d/id.p12" -passout pass:akasha >/dev/null 2>&1 || return 1
  # Import the identity into the login keychain and pre-authorize codesign to use it.
  security import "$d/id.p12" -P akasha -T /usr/bin/codesign >/dev/null 2>&1 || return 1
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
  ( cd "$REPO_DIR/daemon" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$TMP/akasha" ./cmd/akasha ) \
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
if [ "$os" = "darwin" ] && command -v codesign >/dev/null 2>&1; then
  if [ "${AKASHA_ADHOC_SIGN:-0}" != "1" ] && ensure_signing_cert; then
    codesign -s "$SIGN_CN" -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
      && ok "Code-signed with stable local identity — keychain access persists across updates" \
      || { warn "Stable-identity signing failed; falling back to ad-hoc."
           codesign -s - -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
             || warn "codesign failed — daemon may not start under launchd"; }
  else
    codesign -s - -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
      && { ok "Code-signed (ad-hoc)"
           warn "Ad-hoc signing: updating akasha may re-prompt for vault-key keychain access."; } \
      || warn "codesign failed — daemon may not start under launchd"
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
