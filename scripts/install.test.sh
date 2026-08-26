#!/usr/bin/env bash
# Tests for install.sh — drives a full install against a local file:// "release"
# and checks what actually landed on disk.
#
# The cases that matter are the ones where a step fails. An installer that stops
# is recoverable; one that prints a green tick over an empty templates directory
# is not — the user meets it much later as "No templates loaded." and "No
# credentials found.", with nothing pointing back at the install. So every
# failure case below asserts BOTH a non-zero exit and an empty destination.
#
#   bash scripts/install.test.sh
#
# Hermetic: HOME, the install dir, the templates dir and the release base are all
# redirected into a temp tree. Nothing touches a real vault, keychain or PATH.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="${INSTALL:-$ROOT/install.sh}"

fails=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n       %s\n' "$1" "$2"; fails=$((fails + 1)); }

# Same os/arch mapping install.sh does, so the fixture asset has the name the
# script will ask for.
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64)  arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)             arch="unsupported" ;;
esac
ASSET="akasha-${os}-${arch}"

sha256of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── Fixtures ────────────────────────────────────────────────────────────────
# A "release" served over file://. The binary is a stub: nothing in these tests
# executes it, and a real one would only slow the run down.
mk_release() { # mk_release <dir> <templates-tarball|"">
  rel="$1"; mkdir -p "$rel"
  printf '#!/bin/sh\necho stub akasha\n' > "$rel/$ASSET"
  : > "$rel/SHA256SUMS"
  printf '%s  %s\n' "$(sha256of "$rel/$ASSET")" "$ASSET" >> "$rel/SHA256SUMS"
  if [ -n "$2" ]; then
    cp "$2" "$rel/akasha-templates.tar.gz"
    printf '%s  %s\n' "$(sha256of "$rel/akasha-templates.tar.gz")" akasha-templates.tar.gz \
      >> "$rel/SHA256SUMS"
  fi
}

# A well-formed bundle: a top-level templates/ dir, which is the layout
# install_templates_from_tar expects.
good_tar="$WORK/good.tar.gz"
( mkdir -p "$WORK/stage/templates"
  printf 'provider: aws\n'    > "$WORK/stage/templates/aws.yaml"
  printf 'provider: github\n' > "$WORK/stage/templates/github.yaml"
  tar -czf "$good_tar" -C "$WORK/stage" templates )

# Valid archive, wrong layout — tar succeeds and zero templates land. This is
# the case a tar exit-status check alone would still wave through.
wrong_tar="$WORK/wrong.tar.gz"
( mkdir -p "$WORK/stage2/other"
  printf 'provider: aws\n' > "$WORK/stage2/other/aws.yaml"
  tar -czf "$wrong_tar" -C "$WORK/stage2" other )

# Not an archive at all: a truncated or corrupt download.
corrupt_tar="$WORK/corrupt.tar.gz"
printf 'this is not a gzip stream' > "$corrupt_tar"

# ── Runner ──────────────────────────────────────────────────────────────────
# Each run gets a fresh HOME and a fresh cwd. The cwd matters: install.sh treats
# a directory containing daemon/cmd/akasha as "you want YOUR code" and skips the
# download entirely, so the tests must not run from the checkout.
run_install() { # run_install <label> <release-dir> [extra PATH prefix dir]
  RUNHOME="$WORK/home.$1"; rm -rf "$RUNHOME"; mkdir -p "$RUNHOME"
  RUNCWD="$WORK/cwd.$1"; rm -rf "$RUNCWD"; mkdir -p "$RUNCWD"
  TPL="$RUNHOME/.akasha/templates.dist"
  runpath="$PATH"
  [ -n "${3:-}" ] && runpath="$3:$PATH"
  OUT="$(cd "$RUNCWD" && env \
    HOME="$RUNHOME" \
    PATH="$runpath" \
    AKASHA_INSTALL_DIR="$RUNHOME/bin" \
    AKASHA_SHIPPED_TEMPLATES_DIR="$TPL" \
    AKASHA_RELEASE_BASE="file://$2" \
    AKASHA_ADHOC_SIGN=1 \
    AKASHA_SKIP_BACKUP=1 \
    sh "$INSTALL" 2>&1 </dev/null)"
  RC=$?
}

count_yaml() { ls "$1"/*.yaml 2>/dev/null | wc -l | tr -d ' '; }

if [ "$arch" = "unsupported" ]; then
  echo "SKIP: no prebuilt asset name for $(uname -m)"
  exit 0
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "SKIP: curl is required to drive the file:// release fixture"
  exit 0
fi

echo "HAPPY PATH (proves the failure cases below are not vacuous):"
mk_release "$WORK/rel-good" "$good_tar"
run_install good "$WORK/rel-good"
if [ "$RC" -ne 0 ]; then
  fail "clean install exits 0" "rc=$RC
$OUT"
elif [ "$(count_yaml "$TPL")" != "2" ]; then
  fail "clean install lands both templates" "found $(count_yaml "$TPL") in $TPL"
elif ! printf '%s' "$OUT" | grep -q 'Installed 2 provider template'; then
  fail "clean install reports the count it installed" "$OUT"
else
  pass "installs 2 templates, exit 0, count reported"
fi

echo
echo "MUST FAIL LOUDLY (a green tick over an empty install is the bug):"

# tar present but failing — a broken tar, a full disk, an unwritable extract
# dir. This is the unchecked exit status that shipped.
shim="$WORK/shim"; mkdir -p "$shim"
printf '#!/bin/sh\necho "tar: broken" >&2\nexit 127\n' > "$shim/tar"
chmod +x "$shim/tar"
mk_release "$WORK/rel-tarfail" "$good_tar"
run_install tarfail "$WORK/rel-tarfail" "$shim"
if [ "$RC" -eq 0 ]; then
  fail "tar failing must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "tar failing must leave no templates" "found $(count_yaml "$TPL")"
elif ! printf '%s' "$OUT" | grep -qi 'unpack'; then
  fail "tar failure names what broke" "$OUT"
else
  pass "tar exits non-zero -> install fails, 0 templates"
fi

# tar absent entirely — the reproduced case (an arm64 Arch image ships no tar).
# PATH is pared down to the tools install.sh needs, minus tar.
minbin="$WORK/minbin"; mkdir -p "$minbin"
for t in sh mktemp uname tr mkdir curl awk sha256sum shasum install cp rm ls cat sed grep; do
  p="$(command -v "$t" 2>/dev/null)" || continue
  # Wrappers, not symlinks: macOS `shasum` is a perl script that resolves its
  # own version from its path, and refuses to run through a symlink elsewhere.
  printf '#!/bin/sh\nexec %s "$@"\n' "$p" > "$minbin/$t"
  chmod +x "$minbin/$t"
done
rm -f "$minbin/tar"
mk_release "$WORK/rel-notar" "$good_tar"
RUNHOME="$WORK/home.notar"; rm -rf "$RUNHOME"; mkdir -p "$RUNHOME"
RUNCWD="$WORK/cwd.notar"; rm -rf "$RUNCWD"; mkdir -p "$RUNCWD"
TPL="$RUNHOME/.akasha/templates.dist"
OUT="$(cd "$RUNCWD" && env -i \
  HOME="$RUNHOME" \
  PATH="$minbin" \
  AKASHA_INSTALL_DIR="$RUNHOME/bin" \
  AKASHA_SHIPPED_TEMPLATES_DIR="$TPL" \
  AKASHA_RELEASE_BASE="file://$WORK/rel-notar" \
  AKASHA_ADHOC_SIGN=1 \
  AKASHA_SKIP_BACKUP=1 \
  sh "$INSTALL" 2>&1 </dev/null)"
RC=$?
if [ "$RC" -eq 0 ]; then
  fail "missing tar must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "missing tar must leave no templates" "found $(count_yaml "$TPL")"
elif ! printf '%s' "$OUT" | grep -q 'tar'; then
  fail "missing tar is named in the error" "$OUT"
else
  pass "tar absent from PATH -> install fails, 0 templates"
fi

# Corrupt/truncated download that still matches its (recomputed) checksum.
mk_release "$WORK/rel-corrupt" "$corrupt_tar"
run_install corrupt "$WORK/rel-corrupt"
if [ "$RC" -eq 0 ]; then
  fail "corrupt bundle must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "corrupt bundle must leave no templates" "found $(count_yaml "$TPL")"
else
  pass "corrupt bundle -> install fails, 0 templates"
fi

# Archive unpacks fine but carries no templates/ dir. cp matches nothing, and
# nothing about the exit statuses is wrong — only the destination shows it.
mk_release "$WORK/rel-wrong" "$wrong_tar"
run_install wrong "$WORK/rel-wrong"
if [ "$RC" -eq 0 ]; then
  fail "bundle with no templates must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "bundle with no templates must leave none" "found $(count_yaml "$TPL")"
elif ! printf '%s' "$OUT" | grep -q 'No provider templates were installed'; then
  fail "empty install is named as such" "$OUT"
else
  pass "valid archive, no templates/ dir -> install fails"
fi

# The release serves a binary but no bundle at all. This one used to warn and
# exit 0 — an honest warning rather than a false tick, but the same end state:
# a green install with zero providers, met later as "No templates loaded."
# release.yml packages the bundle on every tag, so its absence is a broken
# release, not a release that opted out.
mk_release "$WORK/rel-nobundle" ""
run_install nobundle "$WORK/rel-nobundle"
if [ "$RC" -eq 0 ]; then
  fail "a release with no templates bundle must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "no templates bundle must leave none" "found $(count_yaml "$TPL")"
elif ! printf '%s' "$OUT" | grep -q 'No provider templates published'; then
  fail "a missing bundle is named as such" "$OUT"
else
  pass "no templates bundle in the release -> install fails, 0 templates"
fi

echo
echo "SOURCE BUILD (the other way templates get installed):"

# install_templates_from_source is the fallback path — no release to download
# from, so the templates come out of a checkout instead. It has the same failure
# modes as the tar path and none of the same coverage, and its "this checkout is
# incomplete" refusal is a hard stop that nothing else exercises.
#
# `go` is stubbed. Compiling the daemon proves nothing about template
# installation and would put a minute of Go build into a shell test; the stub
# honours -o and writes a file there, which is all install.sh does with it.
gostub="$WORK/gostub"; mkdir -p "$gostub"
cat > "$gostub/go" <<'STUB'
#!/bin/sh
# Stub `go`: find -o <path>, write a runnable file there, succeed.
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *)  shift ;;
  esac
done
[ -n "$out" ] || exit 1
printf '#!/bin/sh\necho stub akasha\n' > "$out"
chmod +x "$out"
STUB
chmod +x "$gostub/go"

# mk_checkout <dir> <template-count>: a minimal tree with the two directories
# install.sh reaches into. A count of 0 makes daemon/templates exist but hold
# nothing install.sh will copy.
mk_checkout() {
  mkdir -p "$1/daemon/cmd/akasha" "$1/daemon/templates"
  i=0
  while [ "$i" -lt "$2" ]; do
    printf 'provider: p%s\n' "$i" > "$1/daemon/templates/p$i.yaml"
    i=$((i + 1))
  done
}

run_source_install() { # run_source_install <label> <repo-dir>
  RUNHOME="$WORK/home.$1"; rm -rf "$RUNHOME"; mkdir -p "$RUNHOME"
  RUNCWD="$WORK/cwd.$1"; rm -rf "$RUNCWD"; mkdir -p "$RUNCWD"
  TPL="$RUNHOME/.akasha/templates.dist"
  OUT="$(cd "$RUNCWD" && env \
    HOME="$RUNHOME" \
    PATH="$gostub:$PATH" \
    AKASHA_INSTALL_DIR="$RUNHOME/bin" \
    AKASHA_SHIPPED_TEMPLATES_DIR="$TPL" \
    AKASHA_BUILD_FROM_SOURCE=1 \
    AKASHA_REPO_DIR="$2" \
    AKASHA_ADHOC_SIGN=1 \
    AKASHA_SKIP_BACKUP=1 \
    sh "$INSTALL" 2>&1 </dev/null)"
  RC=$?
}

# Happy path first, so the two refusals below are not vacuous.
mk_checkout "$WORK/src-good" 2
run_source_install srcgood "$WORK/src-good"
if [ "$RC" -ne 0 ]; then
  fail "source build with templates exits 0" "rc=$RC
$OUT"
elif [ "$(count_yaml "$TPL")" != "2" ]; then
  fail "source build lands both templates" "found $(count_yaml "$TPL") in $TPL"
else
  pass "source build installs 2 templates, exit 0"
fi

# A checkout with no daemon/templates at all — a sparse clone, a stripped
# tarball, someone running install.sh from the wrong directory. This used to be
# a silent no-op that installed the binary and no providers.
mk_checkout "$WORK/src-notpl" 0
rm -rf "$WORK/src-notpl/daemon/templates"
run_source_install srcnotpl "$WORK/src-notpl"
if [ "$RC" -eq 0 ]; then
  fail "checkout with no templates dir must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "incomplete checkout must leave no templates" "found $(count_yaml "$TPL")"
elif ! printf '%s' "$OUT" | grep -q 'this checkout is incomplete'; then
  fail "incomplete checkout is named as such" "$OUT"
else
  pass "checkout with no daemon/templates -> install fails, 0 templates"
fi

# The directory is there and empty. cp matches nothing and returns 0 through the
# `|| true`, so only the destination count shows it — the source-path twin of
# the wrong-layout tarball above.
mk_checkout "$WORK/src-empty" 0
run_source_install srcempty "$WORK/src-empty"
if [ "$RC" -eq 0 ]; then
  fail "empty templates dir must be fatal" "exited 0
$OUT"
elif [ "$(count_yaml "$TPL")" != "0" ]; then
  fail "empty templates dir must leave none" "found $(count_yaml "$TPL")"
elif ! printf '%s' "$OUT" | grep -q 'No provider templates were installed'; then
  fail "empty source install is named as such" "$OUT"
else
  pass "empty daemon/templates -> install fails, 0 templates"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "all install.sh tests passed"
else
  echo "$fails install.sh test(s) FAILED"
fi
exit $([ "$fails" -eq 0 ] && echo 0 || echo 1)
