package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Linux uses bubblewrap.
//
// Landlock is not merely inferior here, it is disqualified: it has no deny rule.
// You declare handled access types and then GRANT paths, and a more-specific
// grant cannot subtract from a broader one, so "allow everything except
// ~/.akasha" is inexpressible. You would have to grant every sibling in $HOME
// individually — and then `mkdir ~/newproject` creates a directory covered by no
// grant, needing a write on $HOME that was never granted. The agent's own
// workspace breaks. Landlock is right for a deny-default resolver jail; it is
// wrong for this.
//
// bwrap in --dev-bind / / mode is genuinely allow-by-default: the whole host
// passes through, and each subsequent --tmpfs or --bind /dev/null subtracts one
// target. That is exactly the macOS semantics — one mental model, one Spec that
// means the same thing on both platforms, one set of tests. It also has zero
// injection surface: every path is one literal argv element, unlike the macOS
// side where paths become a generated program.

// bwrapEnv overrides the bwrap binary, mirroring the AKASHA_<BACKEND>_BIN
// convention used for resolver backends.
const bwrapEnv = "AKASHA_BWRAP_BIN"

func bwrapPath() (string, error) {
	if p := os.Getenv(bwrapEnv); p != "" {
		if !strings.HasPrefix(p, "/") {
			return "", fmt.Errorf("sandbox: %s must be an absolute path, got %q", bwrapEnv, p)
		}
		return p, nil
	}
	p, err := exec.LookPath("bwrap")
	if err != nil {
		return "", errBwrapMissing
	}
	return p, nil
}

var (
	errBwrapMissing = fmt.Errorf("bubblewrap (bwrap) is not installed")
	errUserNS       = fmt.Errorf("the kernel refused to create a sandbox")
)

// linuxAvailable probes rather than guesses.
//
// bwrap being installed says nothing about whether unprivileged user namespaces
// are permitted: Debian's kernel.unprivileged_userns_clone=0, RHEL's
// user.max_user_namespaces=0 and Ubuntu 24.04's apparmor restriction all break
// it while leaving the binary in place — and a setuid bwrap works despite all
// three. The only reliable oracle is the kernel.
func linuxAvailable() error {
	bin, err := bwrapPath()
	if err != nil {
		return err
	}
	if err := safeBinary(bin); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--dev-bind", "/", "/", "--", "/bin/true").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n\n  probe: %s --dev-bind / / -- /bin/true\n  %s",
			errUserNS, bin, strings.TrimSpace(string(out)))
	}
	return nil
}

// safeBinary refuses a launcher an attacker could replace.
//
// This matters more here than anywhere else in the tree: on Debian and Ubuntu
// bwrap is frequently SETUID ROOT, so a hijackable bwrap is not "a weak
// sandbox", it is local privilege escalation.
func safeBinary(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("sandbox: cannot stat %s: %w", path, err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("sandbox: %s is group- or world-writable, so any local process could replace it; "+
			"bwrap is often setuid root, which makes that privilege escalation rather than a weak sandbox", path)
	}
	dir := path[:strings.LastIndex(path, "/")]
	di, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("sandbox: cannot stat %s: %w", dir, err)
	}
	if di.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("sandbox: %s is group- or world-writable, so %s can be replaced; "+
			"pin a trusted one with %s=/usr/bin/bwrap", dir, path, bwrapEnv)
	}
	return nil
}

func linuxWrap(spec Spec, cmd *exec.Cmd) error {
	bin, err := bwrapPath()
	if err != nil {
		return err
	}
	argv, err := bwrapArgv(spec, bin, append([]string{cmd.Path}, cmd.Args[1:]...))
	if err != nil {
		return err
	}
	cmd.Path = bin
	cmd.Args = argv
	return nil
}

// bwrapArgv builds the launcher argv. Ordering is mechanical: --dev-bind first,
// then namespace flags, then every deny, then every allow-back. Spec.Deny order
// is irrelevant, matching the macOS guarantee.
func bwrapArgv(spec Spec, bin string, command []string) ([]string, error) {
	a := []string{bin, "--dev-bind", "/", "/", "--die-with-parent"}

	if spec.DenyPeerProcesses {
		// Closes /proc/<pid>/environ, today the cheapest way for one agent to
		// steal another's AKASHA_AGENT_KEY. The cost is that ps/pgrep see only
		// this run's own subtree.
		a = append(a, "--unshare-pid", "--proc", "/proc")
	}

	for _, r := range spec.Deny {
		for _, p := range canonicalVariants(r.Path) {
			if r.Tree {
				a = append(a, "--tmpfs", p)
				if r.Mode == DenyAll {
					a = append(a, "--remount-ro", p)
				}
			} else {
				// A denied FILE reads as empty rather than EPERM. The tempting
				// fix — bind a mode-0000 file for errno parity with macOS — is
				// unsound: depending on the uid mapping the child may hold
				// CAP_DAC_OVERRIDE inside the user namespace and read its own
				// 0000 file anyway. Relying on DAC inside a userns is exactly
				// the kind of "looks right, isn't" this package must not
				// contain, so SelfTest's criterion is "no secret bytes", not a
				// specific errno.
				a = append(a, "--bind", "/dev/null", p)
			}
		}
	}

	if spec.DenyKeychain {
		for _, p := range linuxKeyringPaths() {
			a = append(a, "--tmpfs", p)
		}
		// The channel, not just the files. See linuxSecretServicePaths.
		for _, p := range linuxSecretServicePaths() {
			a = append(a, "--bind", "/dev/null", p)
		}
	}
	if spec.DenyDeputies {
		for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
			a = append(a, "--bind", "/dev/null", p)
		}
	}

	for _, p := range spec.AllowSocket {
		// --ro-bind of a unix socket over a tmpfs works: bwrap creates the
		// destination node, and a socket and a regular file are both
		// non-directories, so mount --bind accepts it. This is how flatpak
		// exposes the Wayland and PulseAudio sockets.
		a = append(a, "--ro-bind", p, p)
	}
	for _, p := range spec.AllowRead {
		a = append(a, "--ro-bind", p, p)
	}
	for _, p := range spec.AllowWrite {
		a = append(a, "--bind", p, p)
	}

	a = append(a, "--")
	a = append(a, command...)
	return a, nil
}

func linuxKeyringPaths() []string {
	var p []string
	if h := homeDir(); h != "" {
		p = append(p,
			h+"/.local/share/keyrings",
			h+"/.local/share/kwalletd",
		)
	}
	// gnome-keyring's own control socket lives here, alongside the ssh-agent
	// socket it may also be serving.
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		p = append(p, x+"/keyring")
	}
	return p
}

// linuxSecretServicePaths returns the D-Bus session-bus sockets to mask.
//
// Masking the keyring databases was never enough. The vault does not read those
// files: it calls org.freedesktop.secrets over the SESSION BUS, served by
// gnome-keyring/kwalletd/KeePassXC — processes outside the sandbox, holding the
// unlocked collection in their own memory. Under `--dev-bind / /` the bus socket
// passed straight through, so a supervised agent could ask for the vault key by
// exactly the route the daemon uses. macOS closed the equivalent channel from
// the start (the securityd mach services); this is Linux catching up.
//
// The cost is bluntness: bwrap can mask a socket but cannot filter methods on
// it, so the child loses every other session-bus service too. That is the right
// trade for a credential-isolation run — and it is why the mask is tied to
// DenyKeychain rather than applied unconditionally.
//
// A bus reached through an ABSTRACT socket (unix:abstract=…, still used by
// dbus-launch sessions) has no filesystem object to mask; only unsharing the
// network namespace would close it, and that would take the agent's network
// with it. Such an address is skipped here deliberately — SelfTest performs the
// vault's real keyring read from inside the profile, so an unmaskable bus
// surfaces as a refused launch rather than a silent hole.
func linuxSecretServicePaths() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		// Held to the same rule as any path in the Spec: these come from the
		// environment, and an environment-derived string must not be able to
		// turn into `--bind /dev/null /`.
		if p == "" || seen[p] || validPath(p, "session-bus") != nil {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	for _, p := range dbusUnixPaths(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) {
		add(p)
	}
	// The systemd default, which clients fall back to when the variable is
	// unset — and which is the live socket on essentially every modern desktop.
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		add(x + "/bus")
	}
	add("/run/user/" + itoa(os.Getuid()) + "/bus")
	return out
}

// dbusUnixPaths extracts the filesystem socket paths from a D-Bus address list.
//
// Format per the D-Bus spec: addresses joined by ";", each
// "transport:key=value,key=value", values percent-encoded. Only unix:path=
// yields something a mount can cover; unix:abstract= and every non-unix
// transport are skipped (see linuxSecretServicePaths).
func dbusUnixPaths(addr string) []string {
	var out []string
	for _, one := range strings.Split(addr, ";") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(one), "unix:")
		if !ok {
			continue
		}
		for _, kv := range strings.Split(rest, ",") {
			if v, ok := strings.CutPrefix(kv, "path="); ok {
				out = append(out, dbusUnescape(v))
			}
		}
	}
	return out
}

// dbusUnescape reverses the percent-encoding a D-Bus address value may carry.
// A malformed escape yields "", which the caller drops rather than masking a
// path it only half understood.
func dbusUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return ""
		}
		hi, lo := unhex(s[i+1]), unhex(s[i+2])
		if hi < 0 || lo < 0 {
			return ""
		}
		b.WriteByte(byte(hi<<4 | lo))
		i += 2
	}
	return b.String()
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
