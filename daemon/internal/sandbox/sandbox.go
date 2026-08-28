// Package sandbox launches a child process under an OS sandbox that makes
// Akasha's secret surface unreachable while leaving the rest of the machine
// alone.
//
// The model is ALLOW-BY-DEFAULT with targeted deny, not a jail. An agent needs
// the whole developer machine — compilers, caches, network, the user's repos —
// and a deny-default jail that has to enumerate all of that is a jail that gets
// --no-sandbox'd on day two. What this takes away is the enumerable secret
// surface: the vault database, the audit log, the OS keychain, materialized
// session credentials, and the well-known plaintext credential files. What it
// leaves is one door: the daemon socket, which authenticates, policy-gates and
// audits every vend.
//
// Inside the akasha data directory the polarity INVERTS: the whole subtree is
// denied and the few paths a child legitimately needs are allowed back. A file
// nobody thought of — a rotated audit segment, a future cache, tomorrow's key
// backup — is then denied by construction rather than by enumeration.
//
// # What this is not
//
// This is CONTAINMENT, not identity. The daemon still cannot distinguish a
// sandboxed caller from any other same-user process: both dial the same socket
// and present the same forgeable bearer key. Spec.AllowSocket is a parameter
// rather than a constant precisely so that can change — when the daemon mints a
// per-run listener reachable only from inside the sandbox it built, "identity is
// the sandbox" becomes literally true and nothing here changes. Until then, do
// not describe this as an identity mechanism.
//
// It also does not confine the network, and therefore does not prevent
// exfiltration; and it does not address prompt injection, which corrupts the
// operation rather than the reach.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Mode is what a Rule takes away.
type Mode int

const (
	// DenyAll removes read, write and metadata access — the secret surface.
	DenyAll Mode = iota
	// DenyWrite leaves a path readable but never writable — the integrity
	// surface. Templates and approvals live here: an agent that can drop a
	// template AND forge its approval has code execution in the daemon's
	// resolver.
	DenyWrite
)

// Rule is one path taken away from the child.
type Rule struct {
	Path string // absolute, cleaned, no "..", no control bytes
	Tree bool   // true: the whole subtree; false: this path only
	Mode Mode
	Why  string // one line, surfaced by Describe and by SelfTest failures

	// OS restricts a rule to one platform: "" (both), "darwin" or "linux".
	//
	// The deny set describes a secret surface, and some of that surface only
	// exists on one platform. /Volumes/akasha-sessions and /Library/Keychains
	// are macOS locations, and rendering them on Linux was not merely wasted
	// work: bwrap must create each mount point, an ordinary user cannot create
	// anything at /, and so `akasha run` aborted for every non-root Linux user.
	// Worse, when it DID run as root it created /Volumes and Library/ on the
	// Linux root filesystem — a machine that had once run akasha as root then
	// behaved differently from one that had not.
	//
	// Tagging the rule states the platform fact once, where the path is chosen,
	// instead of leaving each renderer to infer it from a predicate about
	// permissions. It is also the last silent skip in the deny set: everything
	// else a renderer drops, it now says so.
	OS string
}

// appliesTo reports whether this rule belongs in a profile for goos.
func (r Rule) appliesTo(goos string) bool { return r.OS == "" || r.OS == goos }

// Spec is the complete deny surface plus the doors held open.
//
// ORDERING IS FIXED, NOT POSITIONAL: allows always win over denies regardless of
// slice order. macOS renders every Allow after every Deny (SBPL is
// last-match-wins); Linux applies every deny mount before every allow bind. A
// caller therefore cannot create an ordering bug by listing rules in an unlucky
// sequence.
type Spec struct {
	Deny []Rule

	// Allow-backs. Only meaningful inside a denied tree; a path outside every
	// Deny is already allowed and listing it is a no-op.
	AllowRead  []string
	AllowWrite []string

	// AllowReadTry is AllowRead for paths akasha did not create and cannot
	// assume exist — the user's ~/.gitconfig and ssh config today.
	//
	// bwrap's --ro-bind fails the whole launch when its source is missing, so
	// listing these in AllowRead refused to start a run for anyone who had
	// never written a ~/.gitconfig, which on a fresh Linux box is most people.
	// The failure surfaced as "sandbox self-test did not complete", naming
	// neither the file nor the cause.
	//
	// Softening these is safe in the one direction that counts: they are
	// allow-backs INSIDE denied trees (~/.ssh is denied wholesale), so a path
	// that is absent and therefore never bound leaves the deny standing. A
	// missing optional file makes the sandbox tighter, never looser. Paths the
	// user typed (--allow-read) stay in AllowRead, where a typo is an error
	// rather than a silent no-op.
	AllowReadTry []string
	// AllowSocket lists unix sockets that stay connectable — and only
	// connectable. This is the door.
	AllowSocket []string

	// DenyKeychain closes the OS credential store, on both platforms by
	// shutting the IPC channel rather than the files behind it.
	//
	// macOS: the securityd mach services, which is complete — a keychain item
	// is unreachable any other way.
	//
	// Linux: the keyring databases AND the D-Bus session bus, because
	// org.freedesktop.secrets is served over that bus by a daemon living
	// outside the sandbox — masking ~/.local/share/keyrings alone left the
	// channel the vault itself uses wide open. bwrap has no method-level D-Bus
	// filter, so this necessarily costs the child every OTHER session-bus
	// service too (portals, notifications). That is a deliberate trade on a
	// credential-isolation run and the one place the two backends are not
	// equally surgical; a future xdg-dbus-proxy could narrow it to a single
	// name. An abstract-socket bus address cannot be masked by a mount at all —
	// SelfTest is what catches that, by performing the vault's real keyring
	// read from inside the profile.
	DenyKeychain bool

	// DenyPeerProcesses hides sibling processes. Linux: a PID namespace, which
	// closes /proc/<pid>/environ — today the cheapest way for one agent to
	// steal another's AKASHA_AGENT_KEY. macOS: NO-OP, reported by Describe
	// rather than silently ignored.
	DenyPeerProcesses bool

	// DenyDeputies blocks IPC channels that let the child ask an UNSANDBOXED
	// process to read a denied path on its behalf. macOS: AppleEvents and
	// launchservicesd. Both: the docker socket, since an agent with docker can
	// bind-mount the host and make everything else decorative.
	DenyDeputies bool
}

// Available reports whether this host can enforce a sandbox, and if not returns
// an actionable error.
//
// This is a real probe, not a version guess: on Linux it execs bwrap, because
// bwrap being installed says nothing about whether unprivileged user namespaces
// are permitted.
func Available() error { return available() }

// Wrap rewrites cmd to run under this host's sandbox.
//
// It changes ONLY cmd.Path and cmd.Args. Env, Dir, Stdin/Stdout/Stderr,
// ExtraFiles and SysProcAttr are untouched, so a caller keeps every exec.Cmd
// semantic it already depends on — signal forwarding to cmd.Process, exit codes
// via *exec.ExitError from Wait, stdio inheritance. That is why this is a
// decorator rather than a Launch() that builds the Cmd: the launch/signal/
// cleanup block in cmd/akasha/exec.go is carefully ordered and should be reused
// verbatim, and --no-sandbox becomes a literal one-line difference (skip this
// call), which is what you want when auditing a bypass.
//
// After Wrap, cmd.Args[0] is the sandbox launcher, so keep the original argv if
// you need it for error messages.
func Wrap(spec Spec, cmd *exec.Cmd) error {
	if cmd == nil {
		return fmt.Errorf("sandbox: nil command")
	}
	if cmd.Process != nil {
		return fmt.Errorf("sandbox: command already started")
	}
	if cmd.Err != nil {
		return fmt.Errorf("sandbox: command has an error: %w", cmd.Err)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if err := available(); err != nil {
		return err
	}
	return wrap(spec, cmd)
}

// Command is sugar: exec.Command plus Wrap.
func Command(spec Spec, name string, arg ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, arg...)
	if err := Wrap(spec, cmd); err != nil {
		return nil, err
	}
	return cmd, nil
}

// Describe renders the exact enforcement for this host — the SBPL profile text
// or the bwrap argv. For `akasha run --print-profile`, for golden tests, and for
// a bug report. It executes nothing.
func Describe(spec Spec) (string, error) { return DescribeFor(runtime.GOOS, spec) }

// DescribeFor renders enforcement for a named GOOS.
//
// The target OS is a parameter rather than a build constraint so a Linux CI
// runner can fully exercise the macOS renderer — which is the one with the
// generated-code surface, and therefore the one most worth testing. This is why
// the package uses a runtime.GOOS switch instead of _darwin.go/_linux.go files.
func DescribeFor(goos string, spec Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	switch goos {
	case "darwin":
		return renderSBPL(spec)
	case "linux":
		argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"<command>"})
		if err != nil {
			return "", err
		}
		return strings.Join(argv, " \\\n  "), nil
	default:
		return "", fmt.Errorf("sandbox: no backend for %s", goos)
	}
}

// allowedRoots bounds where a rule may point.
//
// A Rule{Path: "/"} reaching the Linux renderer becomes `--tmpfs /`, which
// bricks the host for that process tree; a bug or a hostile config must not be
// able to get there. Every path Akasha derives is under one of these.
var allowedRoots = []string{
	"/Users", "/home", "/root", // home directories
	"/var/home",            // /home resolves here on Silverblue and CoreOS
	"/Volumes",             // macOS RAM disk for session credentials
	"/private/var/folders", // macOS per-user temp
	"/var/folders",         // ditto, pre-canonicalisation
	"/tmp", "/private/tmp", // short-lived run dirs
	"/dev/shm", "/run/user", // Linux tmpfs session dirs
	"/Library/Keychains", // macOS system keychains
	"/var/run", "/run",   // docker socket
	"/etc", // machine-wide credential files
}

// Validate is where the security lives: it is the only thing standing between a
// generated path and a profile or mount that escapes quoting or bricks the host.
func (s Spec) Validate() error {
	// A deny set without a private PID namespace is not a deny set.
	//
	// Where bwrap is setuid — Debian and Ubuntu ship it that way — the child
	// stays in the initial user namespace and /proc/<pid>/root/<path> reaches
	// the host's view of every path the mounts below hide. The namespace is what
	// removes those entries, so a Spec that denies anything while asking to keep
	// peer processes visible is asking for a sandbox that does not sandbox.
	if len(s.Deny) > 0 && !s.DenyPeerProcesses {
		return fmt.Errorf("sandbox: a spec with %d deny rules must also set DenyPeerProcesses — "+
			"without a private PID namespace, /proc/<pid>/root reaches every path they mask "+
			"(this is reachable wherever bwrap is setuid, which is the default on Debian and Ubuntu)",
			len(s.Deny))
	}

	check := validPath
	for _, r := range s.Deny {
		// A mistyped OS would silently drop the rule from BOTH profiles, which
		// is the failure mode this field exists to remove.
		if r.OS != "" && r.OS != "darwin" && r.OS != "linux" {
			return fmt.Errorf("sandbox: deny rule %q has OS %q — must be \"\", \"darwin\" or \"linux\"", r.Path, r.OS)
		}
		if err := check(r.Path, "deny"); err != nil {
			return err
		}
	}
	for _, p := range s.AllowRead {
		if err := check(p, "allow-read"); err != nil {
			return err
		}
	}
	// Optional paths reach a mount argument like any other, so they are held to
	// the same standard. Only their absence is tolerated, not their shape.
	for _, p := range s.AllowReadTry {
		if err := check(p, "allow-read-try"); err != nil {
			return err
		}
	}
	for _, p := range s.AllowWrite {
		if err := check(p, "allow-write"); err != nil {
			return err
		}
	}
	for _, p := range s.AllowSocket {
		if err := check(p, "allow-socket"); err != nil {
			return err
		}
	}
	return nil
}

// validPath is the rule Validate enforces, factored out so paths DERIVED at
// render time — the session-bus sockets in bwrap.go, read out of the
// environment rather than built by Surface — are held to the same standard as
// the ones in the Spec. Anything reaching a mount argument goes through here.
func validPath(p, what string) error {
	{
		if p == "" {
			return fmt.Errorf("sandbox: empty %s path", what)
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("sandbox: %s path %q is not absolute", what, p)
		}
		if filepath.Clean(p) != p {
			return fmt.Errorf("sandbox: %s path %q is not clean (want %q)", what, p, filepath.Clean(p))
		}
		if strings.Contains(p, "..") {
			return fmt.Errorf("sandbox: %s path %q contains ..", what, p)
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 0x20 || p[i] == 0x7f {
				return fmt.Errorf("sandbox: %s path contains a control byte at offset %d: %q", what, i, p)
			}
		}
		if strings.Count(strings.TrimSuffix(p, "/"), "/") < 2 {
			return fmt.Errorf("sandbox: %s path %q is too shallow to deny safely", what, p)
		}
		for _, root := range allowedRoots {
			if p == root || strings.HasPrefix(p, root+"/") {
				return nil
			}
		}
		return fmt.Errorf("sandbox: %s path %q is outside the allowed roots %v", what, p, allowedRoots)
	}
}

// canonicalVariants returns p plus its symlink-resolved form when they differ.
//
// Sandbox rules match the kernel's resolved path: /tmp is /private/tmp on
// macOS, /var is /private/var, and a home directory can itself be a symlink. It
// resolves the deepest EXISTING ancestor and re-appends the remainder, so a path
// that does not exist yet (vault.db-wal between checkpoints) still gets a
// correctly canonicalised rule. Denying a not-yet-existing path is not wasted
// work — it is the only thing between the agent and the file the next SQLite
// checkpoint creates.
func canonicalVariants(p string) []string {
	out := []string{p}
	rest := ""
	probe := p
	for {
		if resolved, err := filepath.EvalSymlinks(probe); err == nil {
			full := filepath.Join(resolved, rest)
			if full != p {
				out = append(out, full)
			}
			return out
		}
		parent := filepath.Dir(probe)
		if parent == probe || strings.Count(parent, "/") < 1 {
			return out
		}
		rest = filepath.Join(filepath.Base(probe), rest)
		probe = parent
	}
}

// homeDir returns the user's home, for building the default surface.
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return os.Getenv("HOME")
}
