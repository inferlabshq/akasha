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
# warn(), but on stdout — for the one "warning" that is really an instruction
# and has to stay in order with the instructions around it. See the PATH hint.
note() { printf '\033[1;33m!\033[0m %s\n' "$1"; }

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
  # Say why the fast path was skipped. Silently returning here sent wget-only
  # machines (Alpine ships wget, not curl) into a source build with nothing but
  # an unexplained "falling back" line to go on.
  command -v curl >/dev/null 2>&1 || { warn "curl is not installed — cannot download the prebuilt binary."; return 1; }

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
  #
  # A missing bundle is a BROKEN RELEASE, not an optional extra: release.yml
  # packages akasha-templates.tar.gz on every tag and lists it in SHA256SUMS, so
  # a release that serves a binary without one has lost an asset. Warning and
  # returning 0 here left the same shape as the bug this whole path exists to
  # kill — an installer that exits green over an empty templates directory, with
  # the consequence deferred to "No templates loaded." and "No credentials
  # found." much later, far from the install that caused it. Every other way of
  # ending up with zero templates is fatal; this one has to be too.
  say "Downloading provider templates (verified)..."
  curl -fsSL "$RELEASE_BASE/akasha-templates.tar.gz" -o "$TMP/templates.tar.gz" \
    || die "No provider templates published at $RELEASE_BASE/akasha-templates.tar.gz.
  The akasha binary is installed, but it would discover nothing without them:
  'akasha template list' would say 'No templates loaded.'
  Every release publishes this bundle, so this is a broken or partial release —
  retry, or build from source: AKASHA_BUILD_FROM_SOURCE=1 sh install.sh"
  twant="$(awk '$2 == "akasha-templates.tar.gz" || $2 == "*akasha-templates.tar.gz" {print $1}' "$TMP/SHA256SUMS")"
  tgot="$(sha256 "$TMP/templates.tar.gz")" || die "Could not compute a SHA256 for the templates bundle — refusing to install unverified.
  install sha256sum (coreutils) or shasum, or build from source:
    AKASHA_BUILD_FROM_SOURCE=1 sh install.sh"
  [ -n "$twant" ] && [ "$twant" = "$tgot" ] || die "Checksum mismatch for templates bundle — refusing to install."
  install_templates_from_tar "$TMP/templates.tar.gz"
  return 0
}

# installed_template_count counts what actually landed in ShippedDir.
#
# This is the only honest success signal available. Every step of a template
# install can fail without `cp` returning non-zero — an empty source glob is
# passed to cp verbatim and the `2>/dev/null || true` that hides that noise
# hides the failure with it — so success is asserted by looking at the
# destination rather than by trusting the commands that wrote to it.
installed_template_count() {
  set -- "$SHIPPED_TEMPLATES_DIR"/*.yaml
  [ -e "$1" ] || { printf '0\n'; return 0; }
  printf '%s\n' "$#"
}

# install_templates_from_tar extracts the bundle (which contains a top-level
# templates/ dir) into ShippedDir.
#
# Failures here are fatal, because the alternative is the worst outcome this
# script can produce. `tar` missing (some minimal images ship none), a truncated
# archive or an unwritable directory all used to print the same green tick as a
# good install; the user met the consequence much later, as `No templates
# loaded.` and `No credentials found.` — a vaulting product that silently vaults
# nothing, handed over as a clean install. An installer that stops is
# recoverable; one that lies is not.
install_templates_from_tar() {
  command -v tar >/dev/null 2>&1 \
    || die "tar is needed to unpack the provider templates, and isn't on PATH.
  The akasha binary is installed; install tar and re-run this script."
  mkdir -p "$SHIPPED_TEMPLATES_DIR" || die "Could not create $SHIPPED_TEMPLATES_DIR"
  tar -xzf "$1" -C "$TMP" || die "Could not unpack the provider templates (truncated or corrupt download).
  The akasha binary is installed; re-run this script to retry."
  cp "$TMP"/templates/*.yaml "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
  # Signatures (if the bundle was signed) confer hands-off trust on the daemon.
  cp "$TMP"/templates/*.yaml.sig "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
  assert_templates_installed
}

# install_templates_from_source copies the curated bundle out of a checkout.
install_templates_from_source() {
  [ -d "$REPO_DIR/daemon/templates" ] \
    || die "No provider templates at $REPO_DIR/daemon/templates — this checkout is incomplete.
  The akasha binary is installed, but it would discover nothing without them."
  mkdir -p "$SHIPPED_TEMPLATES_DIR" || die "Could not create $SHIPPED_TEMPLATES_DIR"
  cp "$REPO_DIR"/daemon/templates/*.yaml "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
  cp "$REPO_DIR"/daemon/templates/*.yaml.sig "$SHIPPED_TEMPLATES_DIR"/ 2>/dev/null || true
  assert_templates_installed
}

assert_templates_installed() {
  n="$(installed_template_count)"
  [ "$n" -gt 0 ] || die "No provider templates were installed into $SHIPPED_TEMPLATES_DIR.
  Akasha would start with no providers: 'akasha template list' would say
  'No templates loaded.' and 'akasha discover' would find nothing.
  Check that $SHIPPED_TEMPLATES_DIR is writable, then re-run this script."
  ok "Installed $n provider template(s) to $SHIPPED_TEMPLATES_DIR"
}

# ── Stable code-signing identity (macOS) ────────────────────────────────────
# Signing is what lets the daemon RUN: launchd refuses an unsigned binary
# (OS_REASON_CODESIGNING) and Apple Silicon kills an unsigned Mach-O outright.
#
# It is NOT what guards the vault key, despite what this comment used to say.
# go-keyring's darwin backend shells out to /usr/bin/security, so the keychain
# item's ACL is written for THAT binary and akasha's own signature never enters
# the check — four differently-signed akasha binaries all read the key with no
# prompt. The block below is kept because a stable identity is still the right
# way to sign (ad-hoc re-identifies the binary on every build, so anything
# pinning akasha — launchd bookkeeping, firewall and MDM rules — sees a new app
# each time), not because it protects a secret. See docs/THREATMODEL.md.
#
# Official release binaries are Developer ID-signed + notarized (see
# .github/workflows/release.yml); this per-machine cert is the source /
# `go install` path. Force ad-hoc with AKASHA_ADHOC_SIGN=1.
SIGN_CN="Akasha Local Code Signing"
SIGN_ID="dev.akasha.daemon"

# NOTE: deliberately no -v. That flag filters to VALID identities, and a
# self-signed certificate is not "valid" — nothing vouches for it — so
# `find-identity -v` reports zero matches even immediately after a successful
# import. With -v this function could never return true, which meant
# ensure_signing_cert always reported failure and every install silently fell
# back to ad-hoc signing.
have_signing_identity() {
  security find-identity -p codesigning 2>/dev/null | grep -qF "$SIGN_CN"
}

# A certificate whose private key is missing or mismatched still lists in
# find-identity and still cannot sign. Whether that has happened is not
# answerable by looking: an imported key is not necessarily labelled with the
# certificate's common name, so searching for one by name gives false negatives
# on healthy keychains. The only reliable question is whether codesign can
# actually use it, which can_sign_with_identity already asks.
#
# So the recovery is driven by that answer rather than by inspection: drop the
# whole identity — delete-identity removes the certificate and its key together,
# which a delete-certificate leaves half-done — and let the next create make a
# matched pair. Without this the broken state is permanent, and the advice the
# installer prints (set-key-partition-list) cannot help, because authorising a
# key that is not there is not the problem.
reset_signing_identity() {
  warn "The local signing identity cannot sign — replacing it."
  n=0
  while [ "$n" -lt 5 ]; do
    security delete-identity -c "$SIGN_CN" >/dev/null 2>&1 || break
    n=$((n + 1))
  done
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

  say "Creating a one-time local code-signing certificate (launchd needs a signed binary; a stable identity keeps it the same across updates)..."
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
  local kc="$HOME/Library/Keychains/login.keychain-db"
  security import "$d/id.p12" -k "$kc" \
    -P akasha -T /usr/bin/codesign >"$d/import.log" 2>&1 || true

  # Fall back to importing the halves separately, because the bundle import is
  # not reliable here: on macOS 22 with both LibreSSL 3.3 and OpenSSL 3.6 it
  # answers "Unknown format in import" and leaves nothing behind.
  #
  # The key must be traditional PKCS#1 ("BEGIN RSA PRIVATE KEY"). Modern openssl
  # writes PKCS#8 ("BEGIN PRIVATE KEY") by default and `security import` rejects
  # that the same way, which is the whole reason this path exists: the
  # CERTIFICATE imports either way, so the failure shows up much later as
  # codesign reporting a missing item for a certificate that is plainly present.
  if ! security find-identity -p codesigning 2>/dev/null | grep -qF "$SIGN_CN"; then
    "$ossl" rsa -in "$d/key.pem" -out "$d/key.pkcs1.pem" >/dev/null 2>&1 || true
    security import "$d/key.pkcs1.pem" -k "$kc" -t priv -f openssl \
      -T /usr/bin/codesign >>"$d/import.log" 2>&1 || true
    security import "$d/cert.pem" -k "$kc" -t cert -f openssl \
      -T /usr/bin/codesign >>"$d/import.log" 2>&1 || true
  fi

  if ! security find-identity -p codesigning 2>/dev/null | grep -qF "$SIGN_CN"; then
    warn "the signing identity would not import: $(tail -1 "$d/import.log")"
    return 1
  fi

  # Authorise codesign to use the key without a prompt. This needs the login
  # keychain password, so it is best-effort: an empty password succeeds only on
  # a keychain that has one. When it does not work the first codesign shows a
  # dialog, which can_sign_with_identity detects rather than hanging on.
  security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || true

  have_signing_identity
}

# preflight_backup_notice asks for a key backup before an existing install is
# replaced. The reason is NOT the signature (see above — that does not gate
# access): it is that the vault key lives in exactly one keychain item, this
# script is about to overwrite the binary that owns it, and a backup is the only
# thing that survives anything going wrong with that item. `akasha vault backup`
# needs your passphrase so we can't run it here — we recommend it. Silence with
# AKASHA_SKIP_BACKUP=1.
preflight_backup_notice() {
  [ "$os" = "darwin" ] || return 0
  [ -e "$BIN" ] || return 0                     # fresh install → nothing to lose
  [ -f "$HOME/.akasha/vault.db" ] || return 0   # no existing vault → nothing to lose
  [ "${AKASHA_SKIP_BACKUP:-0}" = "1" ] && return 0
  warn "An existing akasha vault was found. Your vault key lives in a single OS"
  warn "keychain item, and this will replace the binary that uses it. A key"
  warn "backup is the only recovery if that item is ever lost:"
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
# launchd refuses to run an unsigned binary (OS_REASON_CODESIGNING), so this
# step is what lets the daemon start at all. We prefer a STABLE identity (see
# ensure_signing_cert) so every update presents the same app identity; ad-hoc is
# the graceful fallback and works fine, it just re-identifies the binary each
# build. Neither choice affects access to the vault key.
sign_adhoc() {
  codesign -s - -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
    && { ok "Code-signed (ad-hoc)"
         warn "Ad-hoc signing: each update is a new identity to macOS, so anything pinning"
         warn "akasha (launchd bookkeeping, firewall or MDM rules) may re-ask."; } \
    || warn "codesign failed — daemon may not start under launchd"
}

if [ "$os" = "darwin" ] && command -v codesign >/dev/null 2>&1; then
  if [ "${AKASHA_ADHOC_SIGN:-0}" = "1" ]; then
    sign_adhoc
  elif ensure_signing_cert && { can_sign_with_identity || {
         # One retry only: a stale or half-imported identity is dropped and
         # rebuilt. If the rebuilt one still cannot sign, the cause is the
         # keychain withholding access rather than the identity being wrong,
         # and the guidance in the else branch is the right answer.
         reset_signing_identity
         ensure_signing_cert && can_sign_with_identity
       }; }; then
    codesign -s "$SIGN_CN" -i "$SIGN_ID" -f "$BIN" >/dev/null 2>&1 \
      && ok "Code-signed with a stable local identity — same app identity across updates" \
      || { warn "Stable-identity signing failed; falling back to ad-hoc."; sign_adhoc; }
  else
    # Reached when the identity is missing, OR when it exists but macOS will not
    # let codesign use the key without a GUI prompt. The second case used to
    # hang the install indefinitely; can_sign_with_identity turns it into this
    # message. Explain the one-time fix rather than leaving the stable identity
    # permanently out of reach; ad-hoc below still produces a working install.
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
# Name the rc file the user's shell actually reads. Hardcoding ~/.zshrc is right
# on macOS and wrong on every Linux distro, where the default shell is bash: the
# line landed in a file bash never sources, so the very next instruction we
# print (`akasha setup`) was command-not-found.
#
# The "and right now, in this shell" line is per-branch for the same reason the
# rc file is. fish is not POSIX: `export PATH="...:$PATH"` is a syntax error
# there, so a single shared follow-up line handed fish users a command that
# cannot run — under a correct `fish_add_path` suggestion, which makes it read
# like the whole hint is wrong.
path_hint() {
  case "${SHELL:-}" in
    */fish)
      printf '    fish_add_path %s\n' "$INSTALL_DIR"
      printf '    (then re-open your shell, or run: set -gx PATH %s $PATH)\n' "$INSTALL_DIR" ;;
    */zsh)
      printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc\n' "$INSTALL_DIR"
      printf '    (then re-open your shell, or run: export PATH="%s:$PATH")\n' "$INSTALL_DIR" ;;
    */bash)
      # Linux bash reads ~/.bashrc for interactive shells; macOS Terminal starts
      # bash as a LOGIN shell, which reads ~/.bash_profile and not ~/.bashrc.
      if [ "$os" = "darwin" ]; then
        printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.bash_profile\n' "$INSTALL_DIR"
      else
        printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.bashrc\n' "$INSTALL_DIR"
      fi
      printf '    (then re-open your shell, or run: export PATH="%s:$PATH")\n' "$INSTALL_DIR" ;;
    *)
      # Unknown or unset SHELL (containers, CI, `sh install.sh` under a service
      # account): ~/.profile is the POSIX file every sh-family shell reads.
      printf '    echo '\''export PATH="%s:$PATH"'\'' >> ~/.profile\n' "$INSTALL_DIR"
      printf '    (then re-open your shell, or run: export PATH="%s:$PATH")\n' "$INSTALL_DIR" ;;
  esac
}
# Printed on STDOUT, not through warn(). It is not a warning — it is the first
# step of the "next" block below, and `akasha setup` is command-not-found until
# it is done. Splitting the two across stdout and stderr let them interleave
# whenever both land in one pipe, which put this block's header on one side of
# the setup instructions and its body on the other.
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf '\n'
     note "$INSTALL_DIR is not on your PATH. Add it:"
     path_hint ;;
esac

printf '\n'
ok "Akasha installed. Next:"

# The vault key goes into the freedesktop Secret Service and there is no
# fallback, so on a bare Linux box `akasha setup` is both the next thing a user
# runs and the first thing that fails — previously with a raw D-Bus string.
# It goes here, in the "next" block, because the ordering it describes is not
# discoverable from any error message: a keyring akasha has already woken up
# locked stays locked for the session, and unlocking afterwards does not recover
# it, so the prerequisite has to arrive BEFORE the first run rather than as
# advice after it.
#
# The command still comes first and bare. On a desktop Linux box the keyring is
# already unlocked by the login session, and burying `akasha setup` inside a
# dbus-run-session one-liner made every Linux user read a wall of headless-box
# instructions to find the one command they needed.
printf '    akasha setup\n\n'
if [ "$os" = "linux" ]; then
  printf '    First run only: akasha keeps your vault key in the freedesktop Secret Service\n'
  printf '    (gnome-keyring, KWallet or KeePassXC, over D-Bus). A desktop login unlocks it\n'
  printf '    for you and the line above just works. A headless box, container, WSL or CI\n'
  printf '    runner has none, and must install and UNLOCK one BEFORE that first run:\n\n'
  printf '      sudo apt install gnome-keyring dbus-x11   # dnf/apk/pacman: gnome-keyring dbus\n'
  printf "      dbus-run-session -- sh -c '\n"
  printf "        stty -echo; printf \"keyring password: \"; read P; stty echo; echo\n"
  printf "        printf %%s \"\$P\" | gnome-keyring-daemon --unlock\n"
  printf "        akasha setup'\n"
  printf "      (--unlock reads the password from stdin until EOF, so it must be piped in.)\n\n"
  printf '    If akasha has already failed once, kill the keyring it woke up locked\n'
  printf '    (pkill -f gnome-keyring-daemon) and unlock again — an already-locked\n'
  printf '    collection will not unlock in place.\n\n'
fi
