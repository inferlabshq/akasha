#!/bin/sh
# Render the Homebrew formula for one release from the release's SHA256SUMS.
#
#   scripts/brew-formula.sh v0.1.0-alpha.4 SHA256SUMS > Formula/akasha.rb
#
# The formula installs the same verified prebuilt binary and provider bundle
# that install.sh does, so a `brew install` and a `curl | sh` produce the same
# machine. The release workflow (.github/workflows/release.yml, job `homebrew`)
# runs this on every tag and pushes the result to inferlabshq/homebrew-tap; run
# it by hand only when that job is dormant (no HOMEBREW_TAP_TOKEN).
#
# Every checksum is read from SHA256SUMS, never typed, so the formula cannot
# disagree with what install.sh verifies.
#
# WHY THERE IS A LAUNCHER. The daemon reads its provider bundle from
# ~/.akasha/templates.dist, which install.sh writes. Homebrew cannot write
# there: install runs in a sandbox confined to the prefix, and post_install runs
# under a throwaway HOME (verified: the copy landed in a temp dir and the real
# bundle was untouched). So bin/akasha is a small launcher that mirrors the
# keg's bundle into that directory and execs the real binary in libexec. The
# daemon's helpers re-invoke the binary by absolute path (os.Executable), so a
# sandboxed run never passes through the launcher.
set -eu

usage() { echo "usage: $0 <tag> <SHA256SUMS>" >&2; exit 2; }
tag="${1:-}"; sums="${2:-}"
[ -n "$tag" ] && [ -n "$sums" ] || usage
[ -r "$sums" ] || { echo "$0: cannot read $sums" >&2; exit 1; }
case "$tag" in v*) ;; *) echo "$0: tag must look like vX.Y.Z (got '$tag')" >&2; exit 1 ;; esac

version="${tag#v}"
base="https://github.com/inferlabshq/akasha/releases/download/$tag"

# sum <asset> prints the SHA-256 for one asset. Accepts both `sha256sum` forms
# ("<hash>  <name>" and "<hash> *<name>"). A missing asset is fatal: a formula
# with a blank checksum would fail for every user of that platform.
sum() {
  s="$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1; exit }' "$sums")"
  case "$s" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) echo "$0: no SHA-256 for $1 in $sums" >&2; exit 1 ;;
  esac
  [ "${#s}" -eq 64 ] || { echo "$0: malformed SHA-256 for $1: $s" >&2; exit 1; }
  printf '%s' "$s"
}

darwin_arm64="$(sum akasha-darwin-arm64)"
darwin_amd64="$(sum akasha-darwin-amd64)"
linux_arm64="$(sum akasha-linux-arm64)"
linux_amd64="$(sum akasha-linux-amd64)"
templates="$(sum akasha-templates.tar.gz)"

# The template is a quoted heredoc (no shell expansion) so the launcher's own
# `$` variables survive verbatim; the release values are substituted after.
sed -e "s|@TAG@|$tag|g" \
    -e "s|@VERSION@|$version|g" \
    -e "s|@BASE@|$base|g" \
    -e "s|@DARWIN_ARM64@|$darwin_arm64|g" \
    -e "s|@DARWIN_AMD64@|$darwin_amd64|g" \
    -e "s|@LINUX_ARM64@|$linux_arm64|g" \
    -e "s|@LINUX_AMD64@|$linux_amd64|g" \
    -e "s|@TEMPLATES@|$templates|g" <<'EOF'
# Rendered by scripts/brew-formula.sh in inferlabshq/akasha for @TAG@.
# Do not edit by hand: the release workflow overwrites this file on every tag.
class Akasha < Formula
  desc "Local credential vault an AI agent uses one operation at a time"
  homepage "https://getakasha.dev"
  version "@VERSION@"
  license "Apache-2.0"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    on_arm do
      url "@BASE@/akasha-darwin-arm64"
      sha256 "@DARWIN_ARM64@"
    end
    on_intel do
      url "@BASE@/akasha-darwin-amd64"
      sha256 "@DARWIN_AMD64@"
    end
  end

  on_linux do
    on_arm do
      url "@BASE@/akasha-linux-arm64"
      sha256 "@LINUX_ARM64@"
    end
    on_intel do
      url "@BASE@/akasha-linux-amd64"
      sha256 "@LINUX_AMD64@"
    end
  end

  # Provider templates ship as data, not compiled in. This is the same bundle
  # (and the same checksum) install.sh verifies.
  resource "templates" do
    url "@BASE@/akasha-templates.tar.gz"
    sha256 "@TEMPLATES@"
  end

  def install
    binary = Dir["akasha-*"].first
    odie "no release binary was staged" if binary.nil?
    chmod 0755, binary
    libexec.install binary => "akasha"

    # launchd will not run an unsigned binary. The release build carries the Go
    # linker's ad-hoc signature under the identifier "a.out"; re-sign ad-hoc
    # with the daemon's stable identifier, which is the fallback install.sh
    # uses. A Developer ID signature, once the release pipeline has one, is
    # left exactly as shipped.
    if OS.mac?
      # codesign -dv exits non-zero on an unsigned file; treat that as "sign it".
      sig = begin
        Utils.safe_popen_read("codesign", "-dv", "--verbose=2", libexec/"akasha", err: :out)
      rescue ErrorDuringExecution
        ""
      end
      if sig.empty? || sig.include?("Signature=adhoc")
        system "codesign", "-s", "-", "-i", "dev.akasha.daemon", "-f", libexec/"akasha"
      end
    end

    # The bundle is tar'd with a single top-level templates/ directory, which
    # Homebrew strips while staging; tolerate either layout.
    resource("templates").stage do
      src = File.directory?("templates") ? "templates" : "."
      (pkgshare/"templates").install Dir["#{src}/*.yaml"], Dir["#{src}/*.yaml.sig"]
    end

    # The launcher. The daemon reads its bundle from ~/.akasha/templates.dist
    # and Homebrew cannot write there at install time (the install sandbox is
    # confined to the prefix; post_install runs under a throwaway HOME), so the
    # bundle is mirrored on each invocation instead, which is what install.sh
    # does once at install time. opt_* paths stay valid across upgrades, and
    # the daemon records the exec'd path in its launchd plist.
    (bin/"akasha").write <<~SH
      #!/bin/sh
      # Homebrew launcher for akasha: mirror the keg's provider bundle into the
      # directory the daemon reads, then exec the real binary.
      src="#{opt_pkgshare}/templates"
      if [ -z "${AKASHA_SHIPPED_TEMPLATES_DIR:-}" ] && [ -n "${HOME:-}" ] && [ -d "$src" ]; then
        dist="$HOME/.akasha/templates.dist"
        if { [ -d "$HOME/.akasha" ] || mkdir -m 0700 "$HOME/.akasha"; } 2>/dev/null \\
           && mkdir -p "$dist" 2>/dev/null; then
          for f in "$src"/*.yaml "$src"/*.yaml.sig; do
            [ -f "$f" ] || continue
            t="$dist/${f##*/}"
            if ! cmp -s "$f" "$t" 2>/dev/null; then
              cp "$f" "$t" 2>/dev/null \\
                || { echo "akasha (homebrew): could not refresh $t; the daemon may report 'No templates loaded.'" >&2; break; }
            fi
          done
        fi
      fi
      exec "#{opt_libexec}/akasha" "$@"
    SH
    chmod 0555, bin/"akasha"
  end

  def caveats
    <<~EOS
      Finish the install:

        akasha setup

      It scans for credentials, vaults them on confirmation, registers the
      daemon as a login service, and writes the MCP config for Claude Code.

      On Linux, unlock a Secret Service keyring (gnome-keyring over D-Bus)
      before setup, and install bubblewrap for `akasha run`:
        https://github.com/inferlabshq/akasha/blob/main/docs/getting-started.md#linux-prerequisites

      After `brew upgrade akasha`:  akasha stop && akasha start
      On Linux the systemd unit records the versioned Cellar path, so after an
      upgrade there run `akasha setup` again to re-register the service.

      Alpha: do not use it to protect secrets you cannot rotate.
    EOS
  end

  test do
    # brew test runs with HOME set to testpath, so this also proves the
    # launcher mirrors the bundle where the daemon reads it.
    out = shell_output("#{bin}/akasha version")
    assert_match "akasha @TAG@", out
    assert_match "official trust root: present", out
    assert_path_exists testpath/".akasha/templates.dist/aws.yaml"
    assert_path_exists testpath/".akasha/templates.dist/aws.yaml.sig"
  end
end
EOF
