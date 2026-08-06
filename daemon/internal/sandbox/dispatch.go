package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Platform dispatch uses a runtime.GOOS switch rather than _darwin.go /
// _linux.go build tags, matching the only two platform-specific sites already in
// the tree (policy/approve.go and cmd/akasha/ramdisk.go).
//
// Both backends are os/exec plus string building — no platform-only symbols, so
// there is nothing to make compile. Build tags exist to solve that problem, and
// adding them here would cost the thing that matters most: CI runs on Linux, so
// under tags the SBPL renderer — the one with the generated-code surface —
// would never be exercised there. DescribeFor takes the target GOOS as a
// parameter for exactly that reason.
//
// Introduce a tag when an import forces one (a future Landlock backend needs
// golang.org/x/sys/unix), not preemptively.

func available() error {
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(sandboxExec); err != nil {
			return fmt.Errorf("%s is missing, so akasha has no way to isolate the agent on this macOS build", sandboxExec)
		}
		return nil
	case "linux":
		return linuxAvailable()
	case "windows":
		return fmt.Errorf("akasha run is not available on Windows yet (no sandbox backend) — " +
			"use `akasha exec`, which wires the same broker without isolation")
	default:
		return fmt.Errorf("akasha run has no sandbox backend for %s", runtime.GOOS)
	}
}

func wrap(spec Spec, cmd *exec.Cmd) error {
	switch runtime.GOOS {
	case "darwin":
		return darwinWrap(spec, cmd)
	case "linux":
		return linuxWrap(spec, cmd)
	default:
		return fmt.Errorf("sandbox: no backend for %s", runtime.GOOS)
	}
}

// Explain turns an Available() error into operator-facing guidance: what failed,
// why it matters, how to fix it, and the explicit bypass last.
func Explain(err error) string {
	switch {
	case err == nil:
		return ""
	case errorIs(err, errBwrapMissing):
		return `akasha run: refusing to launch — no sandbox available.

  bubblewrap (bwrap) is not installed. Without it akasha cannot make the vault
  database, the OS keyring, and your plaintext credential files unreachable to
  the agent — which is the entire difference between ` + "`akasha run`" + ` and
  ` + "`akasha exec`" + `.

  Install it:
    Debian/Ubuntu   sudo apt install bubblewrap
    Fedora/RHEL     sudo dnf install bubblewrap
    Arch            sudo pacman -S bubblewrap
    openSUSE        sudo zypper install bubblewrap

  Or run the agent unisolated — it will be able to read your vault and keyring
  directly:

    akasha run <agent> --no-sandbox -- <command>`

	case errorIs(err, errUserNS):
		return `akasha run: refusing to launch — bubblewrap is installed but the kernel
refused to create a sandbox.

` + indent(err.Error()) + `

  Unprivileged user namespaces are disabled on this host. Either:

    1. Enable them (per-distro, needs root):
         Debian    sudo sysctl -w kernel.unprivileged_userns_clone=1
         RHEL      sudo sysctl -w user.max_user_namespaces=15000
         Ubuntu 24.04+
                   sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

    2. Or install a setuid bubblewrap, which does not need them:
         sudo chmod u+s $(command -v bwrap)

  Or run unisolated (the agent can read your vault and keyring directly):
    akasha run <agent> --no-sandbox -- <command>`

	default:
		return "akasha run: refusing to launch — " + err.Error() + `

  Run unisolated only if you accept that the agent can read your vault and
  keyring directly:
    akasha run <agent> --no-sandbox -- <command>`
	}
}

func errorIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func indent(s string) string {
	out := ""
	for _, line := range splitLines(s) {
		out += "  " + line + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
