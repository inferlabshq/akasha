package sandbox

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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

	// ALWAYS, not when a field asks for it.
	//
	// This closes /proc/<pid>/environ, the cheapest way for one agent to steal
	// another's AKASHA_AGENT_KEY — that is what it was added for. But it is also
	// the only thing standing in front of a total bypass of every mount in this
	// function: where bwrap is SETUID (how Debian and Ubuntu ship it) the child
	// stays in the INITIAL user namespace, and /proc/<pid>/root/<path> reaches
	// the host's view of any path we masked. A fresh /proc in a private PID
	// namespace removes those entries.
	//
	// Leaving that behind a struct field meant one caller constructing a Spec
	// without it silently lost every deny at once. Nothing legitimate wants a
	// deny set without it, so the field no longer decides: Validate refuses the
	// combination outright.
	a = append(a, "--unshare-pid", "--proc", "/proc")

	// Trees whose read-only seal is deferred until after the allow-backs. See
	// the note where they are emitted, at the bottom of this function.
	var sealReadOnly []string

	// Directories being replaced wholesale by a tmpfs, decided up front so a
	// deny that lands INSIDE one can be recognised as already covered.
	//
	// Emitting both is not merely redundant, it aborts the launch: the tmpfs
	// replaces the directory, so a nested target no longer exists to mount on,
	// and its deferred --remount-ro dies with
	//
	//	bwrap: Can't remount readonly on /newroot/run/user/1001/akasha:
	//	       realpath(destination): No such file or directory
	//
	// Surface denies $XDG_RUNTIME_DIR/akasha (the session credential dir) and
	// the keychain mask now replaces $XDG_RUNTIME_DIR entirely, so every desktop
	// session hit exactly that. It went unseen because no fixture set
	// XDG_RUNTIME_DIR: with the variable unset the collision cannot arise, and
	// the tests passed on a machine shape almost nobody has.
	var wholeTrees []string
	coveredByTree := func(p string) bool {
		for _, t := range wholeTrees {
			if p == t || strings.HasPrefix(p, strings.TrimSuffix(t, "/")+"/") {
				return true
			}
		}
		return false
	}
	if spec.DenyKeychain {
		if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" && validPath(x, "runtime-dir") == nil {
			for _, t := range mountTargets(x) {
				if denyTargetPlaceable(t) {
					wholeTrees = append(wholeTrees, t)
				}
			}
		}
	}
	for _, t := range wholeTrees {
		a = append(a, "--tmpfs", t)
	}

	for _, r := range spec.Deny {
		if !r.appliesTo("linux") {
			continue // a macOS path; see Rule.OS
		}
		// The RESOLVED target only, not every spelling. A mount masks the
		// directory it lands on, so the symlinked spelling is covered by
		// mounting over what it points AT — while trying to mount at the
		// spelling itself fails outright when a parent is a symlink
		// ("Can't mkdir parents for /home/dev/.akasha" on Silverblue and
		// CoreOS, where /home is a symlink to /var/home). macOS is the
		// opposite case and still wants both, because an SBPL rule is a path
		// pattern rather than a mount — hence this is here and not in
		// canonicalVariants.
		for _, p := range mountTargets(r.Path) {
			if !denyTargetPlaceable(p) || coveredByTree(p) {
				continue
			}
			if r.Tree {
				a = append(a, "--tmpfs", p)
				if r.Mode == DenyAll {
					sealReadOnly = append(sealReadOnly, p)
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
			for _, t := range mountTargets(p) {
				if denyTargetPlaceable(t) && !coveredByTree(t) {
					a = append(a, "--tmpfs", t)
				}
			}
		}

		// The runtime directory was already emitted above, as a TREE, because
		// masking the socket FILE does not hold.
		//
		// A bind mount covers an inode, not a name. Restart the bus — or run the
		// `pkill -f gnome-keyring-daemon` that akasha's OWN error text
		// prescribes — and the daemon unlinks its socket and creates a new one
		// at the same path, beside the mask rather than under it. Proved: the
		// bus reappeared as a live socket inside a running sandbox and returned
		// the vault's ML-KEM key.
		//
		// The same tmpfs closes the other half: a /run/user/<uid> that logind
		// creates AFTER launch could never be masked by a file bind, because at
		// render time there was nothing to bind over and its parent is
		// root-owned so nothing could be created there either. A directory
		// mounted over the runtime dir covers whatever appears inside it later.
		//
		// The cost is the one DenyKeychain already documents: the child loses
		// every OTHER session-bus service too. That was already true of the bus
		// mask; this makes it true of anything else in that directory, which on
		// a credential-isolation run is the trade we are here to make.
		// Any bus path OUTSIDE that directory still needs its own mask.
		for _, p := range linuxSecretServicePaths() {
			for _, t := range mountTargets(p) {
				if denyTargetPlaceable(t) && !coveredByTree(t) {
					a = append(a, "--bind", "/dev/null", t)
				}
			}
		}
	}
	if spec.DenyDeputies {
		// Bind the RESOLVED path, not the spelling. bwrap cannot create a mount
		// destination underneath a symlinked parent — it fails the whole launch
		// with "Can't create file at /var/run/docker.sock: No such file or
		// directory" — and /var/run is a symlink to /run on every systemd distro
		// (ubuntu, debian, fedora all ship it that way). DenyDeputies is on in
		// the default surface, so binding both spellings meant `akasha run`
		// could not start a sandbox on any modern Linux box. --bind-try does not
		// help: the source is not what is missing, the destination's parent is.
		//
		// canonicalVariants collapses the two spellings to one on those distros
		// and leaves them distinct where /var/run is a real directory, so the
		// socket stays masked under whichever names actually exist.
		seen := map[string]bool{}
		for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
			for _, t := range mountTargets(p) {
				// Derived at render time rather than declared in the Spec, so
				// Validate never saw it — hold it to the same standard here,
				// the way the session-bus paths below do.
				if seen[t] || validPath(t, "deny-deputies") != nil || !denyTargetPlaceable(t) {
					continue
				}
				seen[t] = true
				a = append(a, "--bind", "/dev/null", t)
			}
		}
	}

	// Allow-backs mount at a spelling exactly as denies do, so they need the
	// same symlink resolution. Without it, `/home -> /var/home` failed the
	// launch on `~/.gitconfig` after the deny side had already been fixed —
	// the same bug, one list further down.
	for _, p := range mountTargetsAll(spec.AllowSocket) {
		// --ro-bind of a unix socket over a tmpfs works: bwrap creates the
		// destination node, and a socket and a regular file are both
		// non-directories, so mount --bind accepts it. This is how flatpak
		// exposes the Wayland and PulseAudio sockets.
		a = append(a, "--ro-bind", p, p)
	}
	// An allow-back is a hole punched in a deny, so where it RESOLVES decides
	// what it exposes — and the child can change that mid-run. Replace
	// ~/.gitconfig with a symlink to ~/.aws/credentials and the --ro-bind
	// follows it, handing back the file the deny above exists to hide.
	//
	// Dropped loudly rather than silently: every bug in this file's history was
	// a decision that left no trace, so a hole that closes itself must say so.
	for _, p := range mountTargetsAll(spec.AllowRead) {
		if why, bad := resolvesIntoDeny(spec, p); bad {
			log.Printf("akasha sandbox: not allowing %s back — it resolves into %s, which this run denies", p, why)
			continue
		}
		a = append(a, "--ro-bind", p, p)
	}
	// --ro-bind-try is --ro-bind that tolerates a missing source instead of
	// aborting the launch. That is the whole difference, and it is why these
	// paths are tracked separately: a user with no ~/.gitconfig could not start
	// a run at all.
	for _, p := range mountTargetsAll(spec.AllowReadTry) {
		if why, bad := resolvesIntoDeny(spec, p); bad {
			log.Printf("akasha sandbox: not allowing %s back — it resolves into %s, which this run denies", p, why)
			continue
		}
		a = append(a, "--ro-bind-try", p, p)
	}
	for _, p := range mountTargetsAll(spec.AllowWrite) {
		a = append(a, "--bind", p, p)
	}

	// The read-only seal goes on LAST, after every allow-back has been mounted
	// into the tmpfs it belongs to.
	//
	// Sealing at deny time — which is what this did — made the tmpfs read-only
	// before the allow-backs were mounted, and bwrap then could not create the
	// mount point inside it: "Can't create file at /root/.ssh/known_hosts:
	// Read-only file system", which aborts the launch. It only showed up when
	// the optional file EXISTED, so --ro-bind-try (added for the missing case)
	// hid exactly half of it — and ssh creates known_hosts on first connect, so
	// the failing half is the normal state of a developer's machine.
	//
	// Ordering it this way costs nothing: the seal still lands before the child
	// runs, the allow-backs stay read-only (they were mounted --ro-bind), and a
	// path with no allow-back is an empty read-only tmpfs exactly as before.
	// Verified against real bwrap: the allow-back is readable, the private key
	// beside it is not, and the directory rejects writes.
	for _, p := range sealReadOnly {
		a = append(a, "--remount-ro", p)
	}

	a = append(a, "--")
	a = append(a, command...)
	return a, nil
}

// mountTargets returns the path(s) a MOUNT should land on to cover p.
//
// A mount masks the directory it lands on, so mounting over what a symlink
// points at also covers the symlinked spelling — while mounting at the spelling
// itself fails when a parent is a symlink. So for bwrap the resolved form is
// both sufficient and the only one that works, where the macOS renderer wants
// every variant because an SBPL rule matches paths rather than mounting them.
//
// Returns a single element in almost every case; the slice exists so a future
// path that resolves to something genuinely distinct can mask both.
func mountTargets(p string) []string {
	variants := canonicalVariants(p)
	return variants[len(variants)-1:] // resolved form, or p when nothing resolved
}

// denyTargetPlaceable reports whether bwrap can put a mount at p WITHOUT
// creating something it should not.
//
// Every check of `akasha run` until now ran as uid 0, and root can mkdir at /.
// A normal user cannot, so the unconditional denies — `/Volumes/akasha-sessions`
// and `/Library/Keychains`, which are macOS paths rendered on both platforms —
// aborted the launch on every Linux distro:
//
//	bwrap: Can't mkdir parents for /Library/Keychains: Permission denied
//
// Root did not merely hide this. It CREATED those directories on the Linux root
// filesystem, so a machine that had once run akasha as root then behaved
// differently from one that had not.
//
// The question is ONLY whether bwrap can create the mount point, because that
// is the only thing that ever failed. Every original failure was a parent this
// user cannot write to — `/` for the macOS paths, `/run` for the docker socket,
// a `/run/user/<uid>` that no login session had made.
//
// An earlier version also skipped every missing FILE, reasoning that denying
// one buys nothing. That was wrong and it was worse than the bug it replaced.
// A missing file whose parent IS writable can be created by the child a moment
// later, and skipping the mask meant `~/.netrc`, `~/.git-credentials`,
// `~/.pgpass` and the key backup were all READABLE inside the sandbox once
// something made them mid-run — proven with a canary. Before that change those
// paths failed the launch; after it they silently let the child read them,
// which turns a refusal into a hole. The stray 0444 stub that motivated the
// skip is cosmetic; this was not.
//
// What is still skipped is only what this user could not create even if it
// tried, so nothing inside the sandbox can conjure it either. The exception
// worth naming: a path whose parent is root-owned can still be created by a
// ROOT process outside — /run/docker.sock appearing when dockerd starts after
// launch is the real case — and masking that would need the mount point to
// exist first. SelfTest runs at launch and cannot see it.
func denyTargetPlaceable(p string) bool {
	if _, err := os.Lstat(p); err == nil {
		return true // already there; mounting over it creates nothing
	}
	// Walk to the deepest ancestor that EXISTS, and ask whether this user could
	// build the rest of the path from there. bwrap mkdirs the parents it needs,
	// so "creatable" is a question about the chain, not about one directory.
	//
	// Stopping at filepath.Dir was a leak on any fresh account: ~/.config does
	// not exist until something makes it, so ~/.config/gh and ~/.config/gcloud
	// were skipped as unplaceable — while $HOME sat there writable, so the child
	// could create both and read them straight back. Proved with a canary:
	// `LEAK config-gh -> GH-OAUTH-TOKEN-CANARY`. The same held for
	// ~/.local/share/keyrings on a machine that had never run a keyring.
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		fi, err := os.Stat(dir)
		if err == nil {
			return fi.IsDir() && unix.Access(dir, unix.W_OK) == nil
		}
		if parent := filepath.Dir(dir); parent == dir {
			return false // reached the root without finding anything
		}
	}
}

// mountTargetsAll resolves a whole allow-back list, preserving order and
// dropping duplicates that resolution collapses together.
func mountTargetsAll(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		for _, t := range mountTargets(p) {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// resolvesIntoDeny reports whether an allow-back's REAL target sits inside a
// denied tree, and names the tree.
//
// The allow-back list is written against the paths a spec intends; symlinks
// decide what those paths actually reach, and anything running as this user can
// rewrite one between Surface() and the launch.
func resolvesIntoDeny(spec Spec, allow string) (string, bool) {
	real, err := filepath.EvalSymlinks(allow)
	if err != nil || real == allow {
		return "", false // absent, or pointing where it says
	}
	for _, r := range spec.Deny {
		for _, d := range mountTargets(r.Path) {
			if real == d || strings.HasPrefix(real, strings.TrimSuffix(d, "/")+"/") {
				return d, true
			}
		}
	}
	return "", false
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
