package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// listenUnix creates a real socket, because the surface now requires the
// ssh-agent door to BE one and a placeholder file would silently be refused.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	// sun_path is 104 bytes on darwin, and t.TempDir() alone overruns it — hence
	// shortHome below rather than the usual temp directory.
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
}

// shortHome is t.TempDir() for tests that must bind a real unix socket: the
// standard temp path is long enough on darwin to blow sun_path on its own.
func shortHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ak")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// argvPairs returns the operand(s) following each occurrence of flag.
func argvPairs(argv []string, flag string, operands int) [][]string {
	var out [][]string
	for i := 0; i < len(argv); i++ {
		if argv[i] == flag && i+operands < len(argv) {
			out = append(out, argv[i+1:i+1+operands])
		}
	}
	return out
}

func readDirFor(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	e, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The island's whole reason to exist: an excluded name is ABSENT inside, so a
// path created there after launch has nothing to appear at.
//
// No predicate about placeability could reach this. Nothing under /run is
// creatable by the user akasha runs as, so denyTargetPlaceable correctly said
// "no" and the mask was skipped — leaving /run/docker.sock (root-equivalent) and
// /run/user/<uid> (the whole keyring and bus surface) unmasked whenever the
// creating daemon started after the sandbox did.
func TestIslandLeavesExcludedNamesAbsentRatherThanMasked(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"docker.sock", "systemd", "user"} {
		if err := os.Mkdir(filepath.Join(root, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	excluded := map[string]bool{"user": true, "docker.sock": true}
	args := islandArgs(root, excluded, readDirFor(t, root), os.Readlink)

	if got := argvPairs(args, "--tmpfs", 1); len(got) != 1 || got[0][0] != root {
		t.Fatalf("the island must open by replacing %s with a tmpfs, got %v", root, args)
	}
	joined := strings.Join(args, " ")
	for _, n := range []string{"user", "docker.sock"} {
		if strings.Contains(joined, filepath.Join(root, n)) {
			t.Errorf("%s was rebound; an excluded name must not appear in the argv at all, "+
				"or a path created there after launch becomes visible:\n%s", n, joined)
		}
	}
	// …and the rest of /run is still there, or the island has broken DNS, the
	// system bus, and nss for no credential-surface gain.
	if !strings.Contains(joined, "--bind-try "+filepath.Join(root, "systemd")) {
		t.Errorf("systemd was not rebound; the island must freeze /run, not empty it:\n%s", joined)
	}
}

// A symlink is recreated as a symlink. --ro-bind FOLLOWS it and mounts the
// target under the link's name, which on a host whose /run holds a link into a
// denied directory hands that content straight back through the island — the
// same class of bug this package already shipped once on the allow-back list.
func TestIslandRecreatesSymlinksInsteadOfBindingThem(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "denied")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	args := islandArgs(root, nil, readDirFor(t, root), os.Readlink)

	link := filepath.Join(root, "link")
	sym := argvPairs(args, "--symlink", 2)
	if len(sym) != 1 || sym[0][0] != secret || sym[0][1] != link {
		t.Fatalf("want --symlink %s %s, got %v", secret, link, args)
	}
	for _, p := range argvPairs(args, "--bind-try", 2) {
		if p[1] == link {
			t.Errorf("the symlink was bound as well as recreated; --ro-bind/--bind of a link "+
				"mounts its TARGET under the link's name: %v", args)
		}
	}
}

// covers() decides whether the deny loop may skip a rule, so its precision is
// load-bearing in both directions. Too broad and a deny under a REBOUND entry is
// silently dropped while the host content stays live behind it; too narrow and
// bwrap is asked to mount twice at one target.
func TestIslandCoversOnlyWhatItActuallyRemoved(t *testing.T) {
	ip := islandPlan{root: "/run", excluded: map[string]bool{"user": true}}
	for _, c := range []struct {
		path string
		want bool
		why  string
	}{
		{"/run", true, "the island root itself"},
		{"/run/user", true, "an excluded entry"},
		{"/run/user/1001/bus", true, "anything under an excluded entry cannot exist"},
		{"/run/systemd", false, "a rebound entry is live host content and still needs its own mask"},
		{"/run/systemd/secret", false, "nested under a rebound entry, likewise"},
		{"/run/userdata", false, "a name that merely starts with an excluded one"},
		{"/home/dev/.aws", false, "outside the island"},
	} {
		if got := ip.covers(c.path); got != c.want {
			t.Errorf("covers(%q) = %v, want %v — %s", c.path, got, c.want, c.why)
		}
	}
}

// The island must not narrow what allow-by-default granted. Every kept entry is
// rebound read-write, exactly as --dev-bind / / had it: an island freezes /run's
// top level, it does not seal it.
func TestIslandRebindsWritable(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	args := islandArgs(root, nil, readDirFor(t, root), os.Readlink)
	if strings.Contains(strings.Join(args, " "), "--ro-bind") {
		t.Errorf("a kept entry was rebound read-only; the child could write there before "+
			"the island existed and an island is not a place to tighten that: %v", args)
	}
}

// The ssh-agent socket must survive the keychain masks.
//
// gnome-keyring serves ssh-agent from $XDG_RUNTIME_DIR/keyring/ssh, and both the
// runtime directory and the keyring directory are masked — so every `git push`
// over agent auth failed inside `akasha run`, which is the only mechanism the
// behavioural test found that gets a model to broker at all.
func TestSSHAgentSocketIsHeldOpen(t *testing.T) {
	home := shortHome(t)
	t.Setenv("HOME", home)
	sock := filepath.Join(home, "agent.sock")
	listenUnix(t, sock)
	t.Setenv("SSH_AUTH_SOCK", sock)

	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)
	var found bool
	for _, p := range spec.AllowSocketTry {
		if p == sock {
			found = true
		}
	}
	if !found {
		t.Fatalf("SSH_AUTH_SOCK is not in AllowSocketTry: %v", spec.AllowSocketTry)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("the spec must still validate: %v", err)
	}

	argv, err := bwrapArgv(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	// -try, not a hard bind: no agent running is an ordinary state and must not
	// stop a run, unlike the run socket akasha creates itself.
	var bound bool
	for _, p := range argvPairs(argv, "--ro-bind-try", 2) {
		if p[0] == sock && p[1] == sock {
			bound = true
		}
	}
	if !bound {
		t.Errorf("the agent socket is not bound back with --ro-bind-try:\n%s", strings.Join(argv, " "))
	}
}

// A junk SSH_AUTH_SOCK must not reach the Spec. It is environment-derived, so it
// gets the same treatment as any path in the deny set rather than being trusted
// for being conventional.
func TestJunkSSHAuthSockIsRefusedNotRendered(t *testing.T) {
	home := shortHome(t)
	t.Setenv("HOME", home)
	// A regular file inside a DENIED tree is the one that matters: binding it
	// back would hand the child the very bytes the deny exists to hide.
	deniedFile := filepath.Join(home, ".aws", "credentials")
	if err := os.MkdirAll(filepath.Dir(deniedFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deniedFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"relative/agent.sock",                   // not absolute
		"/etc",                                  // too shallow to be a door
		"/",                                     // the root itself
		"/tmp/../etc/shadow",                    // ".." that a premature Clean used to erase
		deniedFile,                              // a real file, inside a real deny
		filepath.Join(home, "nonexistent.sock"), // nothing there to verify
	} {
		t.Setenv("SSH_AUTH_SOCK", bad)
		spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)
		if len(spec.AllowSocketTry) != 0 {
			t.Errorf("SSH_AUTH_SOCK=%q was accepted as a door: %v", bad, spec.AllowSocketTry)
		}
	}
}
