package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// argvHasBind reports whether argv contains `--bind /dev/null <path>` in order.
func argvHasBind(argv []string, path string) bool {
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--bind" && argv[i+1] == "/dev/null" && argv[i+2] == path {
			return true
		}
	}
	return false
}

func argvHasTmpfs(argv []string, path string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--tmpfs" && argv[i+1] == path {
			return true
		}
	}
	return false
}

// DenyKeychain masked ~/.local/share/keyrings and stopped there — but the vault
// does not read those files. It calls org.freedesktop.secrets over the D-Bus
// session bus, served by a daemon OUTSIDE the sandbox, and under --dev-bind / /
// that socket passed straight through. The agent could ask for the vault key by
// exactly the route the daemon uses, on a profile that reported success.
func TestDenyKeychainClosesTheSessionBus(t *testing.T) {
	// Resolved, because the renderer mounts the symlink-RESOLVED target and on
	// macOS t.TempDir() hands back /var/... which is really /private/var/...
	rt, rtErr := filepath.EvalSymlinks(t.TempDir())
	if rtErr != nil {
		t.Fatal(rtErr)
	}
	if err := os.WriteFile(rt+"/bus", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rt+"/keyring", 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+rt+"/bus")

	argv, err := bwrapArgv(Spec{DenyKeychain: true}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if !argvMasks(argv, rt+"/bus") {
		t.Fatalf("the session bus was left reachable:\n%s", strings.Join(argv, " "))
	}
	// The files still go too — a keyring database readable directly is its own
	// path to the same secret.
	if !argvMasks(argv, rt+"/keyring") {
		t.Errorf("gnome-keyring's control socket directory was not masked")
	}
}

// Without DenyKeychain nothing is masked: the bus mask is a consequence of
// closing the credential store, not an unconditional policy. It costs the child
// every other session-bus service, so it must not apply where it was not asked
// for.
func TestSessionBusSurvivesWithoutDenyKeychain(t *testing.T) {
	// Resolved, because the renderer mounts the symlink-RESOLVED target and on
	// macOS t.TempDir() hands back /var/... which is really /private/var/...
	rt, rtErr := filepath.EvalSymlinks(t.TempDir())
	if rtErr != nil {
		t.Fatal(rtErr)
	}
	if err := os.WriteFile(rt+"/bus", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rt+"/keyring", 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+rt+"/bus")

	argv, err := bwrapArgv(Spec{}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if argvMasks(argv, rt+"/bus") {
		t.Fatal("the session bus was masked on a spec that never asked to deny the keychain")
	}
}

// The systemd default is the live socket even when the variable is unset, and
// a client falls back to it. Masking only what the variable names would leave
// that fallback open.
func TestSessionBusFallbacksAreMasked(t *testing.T) {
	// Resolved, because the renderer mounts the symlink-RESOLVED target and on
	// macOS t.TempDir() hands back /var/... which is really /private/var/...
	rt, rtErr := filepath.EvalSymlinks(t.TempDir())
	if rtErr != nil {
		t.Fatal(rtErr)
	}
	if err := os.WriteFile(rt+"/bus", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rt+"/keyring", 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")

	argv, err := bwrapArgv(Spec{DenyKeychain: true}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if !argvMasks(argv, rt+"/bus") {
		t.Fatalf("the XDG_RUNTIME_DIR fallback bus was not masked:\n%s", strings.Join(argv, " "))
	}
}

func TestDBusAddressParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		want []string
	}{
		{"systemd", "unix:path=/run/user/1000/bus", []string{"/run/user/1000/bus"}},
		{"with guid", "unix:path=/run/user/1000/bus,guid=deadbeef", []string{"/run/user/1000/bus"}},
		{"percent-encoded", "unix:path=/run/user/1000/my%20bus", []string{"/run/user/1000/my bus"}},
		{"several addresses", "unix:path=/run/a;unix:path=/run/b", []string{"/run/a", "/run/b"}},
		// Abstract sockets live in the network namespace, not the filesystem:
		// there is nothing for a mount to cover. Skipped, never guessed at.
		{"abstract", "unix:abstract=/tmp/dbus-Xyz,guid=abc", nil},
		{"tcp", "tcp:host=127.0.0.1,port=1234", nil},
		{"empty", "", nil},
		{"malformed escape", "unix:path=/run/user/%zz", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dbusUnixPaths(tc.addr)
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}

// These paths come from the ENVIRONMENT, unlike everything in the Spec, so they
// get the same validation. `--bind /dev/null /` would be a very bad way to
// learn that.
func TestSessionBusPathsAreValidated(t *testing.T) {
	for _, addr := range []string{
		"unix:path=/",
		"unix:path=/bus",             // too shallow to deny safely
		"unix:path=/etc/../etc/bus",  // not clean
		"unix:path=relative/bus",     // not absolute
		"unix:path=/nowhere/near/it", // outside the allowed roots
	} {
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
		t.Setenv("XDG_RUNTIME_DIR", "")
		for _, p := range linuxSecretServicePaths() {
			if err := validPath(p, "session-bus"); err != nil {
				t.Errorf("%s produced an unvalidated mount path %q: %v", addr, p, err)
			}
		}
	}
}

// Every mount argument must survive Validate's rule, whatever its origin.
func TestDescribeForLinuxStaysValid(t *testing.T) {
	// Resolved, because the renderer mounts the symlink-RESOLVED target and on
	// macOS t.TempDir() hands back /var/... which is really /private/var/...
	rt, rtErr := filepath.EvalSymlinks(t.TempDir())
	if rtErr != nil {
		t.Fatal(rtErr)
	}
	if err := os.WriteFile(rt+"/bus", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rt+"/keyring", 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+rt+"/bus")

	out, err := DescribeFor("linux", Surface(t.TempDir()+"/.akasha", t.TempDir()+"/run", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	// The bus is closed by replacing the directory that resolves its name, so
	// the profile shows the runtime dir rather than the socket. Either is a
	// correct answer to "is the bus shut"; naming only the socket made this an
	// assertion about the mechanism.
	if !strings.Contains(out, rt) {
		t.Errorf("the rendered profile does not show the session bus being closed:\n%s", out)
	}
}

// argvMasks reports whether path is unreachable inside, by EITHER mechanism:
// bound over with /dev/null, or sitting inside a directory replaced by a tmpfs.
//
// The tests here used to assert the bind specifically, which made them
// assertions about the implementation rather than the property. When the
// runtime directory started being replaced wholesale — because a bind covers an
// inode and loses to unlink+recreate — they failed while the bus was MORE
// thoroughly masked than before.
func argvMasks(argv []string, path string) bool {
	if argvHasBind(argv, path) {
		return true
	}
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] != "--tmpfs" {
			continue
		}
		t := strings.TrimSuffix(argv[i+1], "/")
		if path == t || strings.HasPrefix(path, t+"/") {
			return true
		}
	}
	return false
}

// argvHasRoBindTry reports whether argv contains `--ro-bind-try <path> <path>`.
func argvHasRoBindTry(argv []string, path string) bool {
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--ro-bind-try" && argv[i+1] == path && argv[i+2] == path {
			return true
		}
	}
	return false
}

func argvHasRoBind(argv []string, path string) bool {
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--ro-bind" && argv[i+1] == path && argv[i+2] == path {
			return true
		}
	}
	return false
}

// The user's gitconfig and ssh config are allow-backs punched through denied
// trees, and akasha does not create any of them. bwrap's --ro-bind aborts the
// entire launch when its source is missing, so binding them unconditionally
// meant nobody without a ~/.gitconfig could start a run at all — and on a fresh
// Linux box that is most people. It surfaced as "sandbox self-test did not
// complete", which names neither the file nor the reason.
//
// Env ownership is the only mechanism that reliably keeps an agent off raw
// credentials, so this failing closed on a missing optional file took the whole
// feature down with it.
func TestBwrapUsesRoBindTryForOptionalPaths(t *testing.T) {
	// Surface reads the real HOME, and the point of the test is a home where
	// none of these files exist.
	// Resolved, because allow-backs now render the symlink-resolved target and
	// on macOS t.TempDir() hands back /var/... which is really /private/var/...
	home, homeErr := filepath.EvalSymlinks(t.TempDir())
	if homeErr != nil {
		t.Fatal(homeErr)
	}
	t.Setenv("HOME", home)
	spec := Surface(home+"/.akasha", "/tmp/akasha-run-1", nil, nil)

	optional := []string{home + "/.gitconfig", home + "/.ssh/config", home + "/.ssh/known_hosts"}
	for _, p := range optional {
		if !contains(spec.AllowReadTry, p) {
			t.Errorf("%s should be optional (AllowReadTry), got AllowRead=%v AllowReadTry=%v",
				p, spec.AllowRead, spec.AllowReadTry)
		}
		if contains(spec.AllowRead, p) {
			t.Errorf("%s must not be a required bind — a missing one aborts the launch", p)
		}
	}

	argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range optional {
		if !argvHasRoBindTry(argv, p) {
			t.Errorf("expected --ro-bind-try for %s, argv=%v", p, argv)
		}
		if argvHasRoBind(argv, p) {
			t.Errorf("%s is still a hard --ro-bind; a missing file will abort the launch", p)
		}
	}
}

// The softening applies ONLY to paths akasha did not create. A path the user
// typed on --allow-read stays a hard bind, so a typo is an error rather than a
// silently missing door.
func TestBwrapKeepsUserSuppliedReadsRequired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	spec := Surface("/home/u/.akasha", "/tmp/akasha-run-1", []string{"/data/typo"}, nil)
	if !contains(spec.AllowRead, "/data/typo") {
		t.Fatalf("--allow-read paths must stay required: %v", spec.AllowRead)
	}
	argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHasRoBind(argv, "/data/typo") {
		t.Errorf("expected a hard --ro-bind for a user-supplied path, argv=%v", argv)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// bwrap will not create a mount destination underneath a symlinked parent: it
// fails the ENTIRE launch with "Can't create file at /var/run/docker.sock". And
// /var/run is a symlink to /run on every systemd distro — ubuntu, debian and
// fedora all ship it that way. DenyDeputies is on in the default surface, so
// binding both spellings meant `akasha run` could not start a sandbox on any
// modern Linux box, which is the whole feature.
//
// --bind-try does NOT rescue this: what is missing is the destination's parent,
// not the source.
func TestBwrapBindsDockerSocketThroughResolvedPathOnly(t *testing.T) {
	argv, err := bwrapArgv(Spec{DenyDeputies: true}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}

	// Whatever this host resolves them to, no two binds may name the same
	// destination, and each destination must be the resolved spelling.
	seen := map[string]bool{}
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] != "--bind" || argv[i+1] != "/dev/null" {
			continue
		}
		dest := argv[i+2]
		if !strings.Contains(dest, "docker.sock") {
			continue
		}
		if seen[dest] {
			t.Errorf("docker.sock bound twice at the same destination %q", dest)
		}
		seen[dest] = true

		variants := canonicalVariants(dest)
		if resolved := variants[len(variants)-1]; resolved != dest {
			t.Errorf("bound %q, which resolves to %q — bwrap cannot create a mount point "+
				"under a symlinked parent and will fail the launch", dest, resolved)
		}
	}
	if len(seen) == 0 {
		t.Fatal("DenyDeputies bound no docker socket at all — the deputy door is open")
	}
}

// A deny whose target does not exist YET must still be a deny.
//
// This is the test that was missing when a "skip what cannot be mounted" rule
// went in. The rule was needed — bwrap aborts the launch when it cannot create
// the mount point, which is why `akasha run` failed for every non-root user —
// but it was written to skip every missing FILE, and a missing file whose
// parent is writable is exactly the one the child can create a moment later.
// ~/.netrc, ~/.git-credentials, ~/.pgpass and the key backup were all readable
// inside the sandbox once something made them mid-run. That turned a refusal
// into a hole, which is the worse direction.
//
// So: a path this user COULD create must be masked whether or not it is there
// at render time, and only a path nothing running as this user could conjure —
// /Library/Keychains on a Linux box, under a root-owned / — may be skipped.
func TestAbsentButCreatableDenyTargetsAreStillMasked(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// Deliberately create NONE of them: absent at render is the whole point.
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)
	argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{".netrc", ".git-credentials", ".pgpass", "akasha-backup" + "." + "akb"} {
		p := home + "/" + rel
		if !argvHasBind(argv, p) {
			t.Errorf("%s is absent but creatable by this user, and was left unmasked — "+
				"anything that makes it during the run can then read it from inside", p)
		}
	}

	// The counterpart: a path under a root-owned parent stays skipped, because
	// nothing running as this user can bring it into being either. Skipping it
	// is what lets the launch happen at all.
	if argvHasTmpfs(argv, "/Library/Keychains") && os.Geteuid() != 0 {
		if _, statErr := os.Stat("/Library"); statErr != nil {
			t.Error("/Library/Keychains was mounted on a host where it does not exist and " +
				"this user cannot create it — that is the mount that aborted every non-root launch")
		}
	}
}

// A path is "creatable" if this user could build the whole chain, not if its
// immediate parent happens to exist already.
//
// Stopping at filepath.Dir leaked on any fresh account: ~/.config does not
// exist until something makes it, so ~/.config/gh and ~/.config/gcloud were
// skipped as unplaceable while $HOME sat there writable — and the child could
// then create both and read them straight back.
func TestDenyTargetsUnderAMissingButCreatableParentAreMasked(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	// Deliberately do NOT create ~/.config or ~/.local: a fresh account.

	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)
	argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{".config/gh", ".config/gcloud"} {
		if !argvHasTmpfs(argv, home+"/"+rel) {
			t.Errorf("%s sits under a parent that does not exist YET but that this user can "+
				"create, and it was left unmasked — the child makes it and reads it back", rel)
		}
	}
}

// A bind mount covers an inode, not a name. Masking the bus FILE was defeated by
// restarting the bus, which unlinks the socket and creates a new one at the same
// path — beside the mask rather than under it. `pkill -f gnome-keyring-daemon`,
// which akasha's own error text prescribes, is one way to trigger it.
//
// The runtime directory is masked as a tree instead, which also covers a
// /run/user/<uid> that logind creates after launch: at render time there was
// nothing to bind over, and its parent is root-owned so nothing could be
// created there either.
func TestRuntimeDirIsMaskedAsATree(t *testing.T) {
	rt, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+rt+"/bus")
	if err := os.WriteFile(rt+"/bus", nil, 0600); err != nil {
		t.Fatal(err)
	}

	argv, err := bwrapArgv(Spec{DenyKeychain: true}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHasTmpfs(argv, rt) {
		t.Fatalf("the runtime directory was not masked as a tree, so a bus recreated at the "+
			"same path reappears beside the mask:\n%s", strings.Join(argv, " "))
	}
}

// The PID namespace is what stands in front of a total bypass of every mount
// this package emits.
//
// Where bwrap is SETUID — how Debian and Ubuntu ship it — the child stays in the
// INITIAL user namespace, and /proc/<pid>/root/<path> reaches the host's view of
// any path we masked. A fresh /proc in a private PID namespace removes those
// entries. Leaving it behind a struct field meant one caller building a Spec
// without it silently lost every deny at once.
func TestPidNamespaceIsNotOptional(t *testing.T) {
	// Emitted even for a Spec that does not ask for it.
	argv, err := bwrapArgv(Spec{}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	var sawUnshare, sawProc bool
	for i, a := range argv {
		if a == "--unshare-pid" {
			sawUnshare = true
		}
		if a == "--proc" && i+1 < len(argv) && argv[i+1] == "/proc" {
			sawProc = true
		}
	}
	if !sawUnshare || !sawProc {
		t.Errorf("no private PID namespace, so /proc/<pid>/root walks past every mask:\n%s",
			strings.Join(argv, " "))
	}

	// And a deny set that asks to keep peer processes visible is refused, rather
	// than rendered into a sandbox that does not sandbox.
	s := Spec{Deny: []Rule{{Path: "/Users/me/.akasha", Tree: true, Mode: DenyAll}}}
	if err := s.Validate(); err == nil {
		t.Error("Validate accepted a deny set with DenyPeerProcesses false")
	} else if !strings.Contains(err.Error(), "DenyPeerProcesses") {
		t.Errorf("the refusal should name the field and why, got: %v", err)
	}
}

// An allow-back is a hole punched in a deny, so where it RESOLVES decides what
// it exposes — and anything running as this user can change that between
// Surface() and the launch. Replace ~/.gitconfig with a symlink to the
// credentials file and the --ro-bind follows it, handing back exactly what the
// deny beside it exists to hide.
func TestAllowBackThatResolvesIntoADenyIsDropped(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if err := os.MkdirAll(home+"/.aws", 0700); err != nil {
		t.Fatal(err)
	}
	secret := home + "/.aws/credentials"
	if err := os.WriteFile(secret, []byte("[default]\naws_secret_access_key = CANARY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The swap: an allowed-back path now points inside a denied tree.
	if err := os.Symlink(secret, home+"/.gitconfig"); err != nil {
		t.Fatal(err)
	}

	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)
	argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+2 < len(argv); i++ {
		if (argv[i] == "--ro-bind" || argv[i] == "--ro-bind-try") && argv[i+1] == home+"/.gitconfig" {
			t.Fatalf("~/.gitconfig resolves into the denied ~/.aws and was still allowed back, "+
				"which hands the child the credentials file:\n%s", strings.Join(argv, " "))
		}
	}
}
