package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The write side: a run must not be able to leave code where the user runs it
// later. Surface carries the rules; the renderers have to treat an absent
// target correctly on each platform; and the real sandbox has to refuse the
// write while still allowing the read.

func TestSurfaceCarriesWriteSideRules(t *testing.T) {
	home := homeDir()
	if home == "" {
		t.Skip("no home")
	}
	spec := Surface("/tmp/akasha-test-data", "/tmp/akasha-test-run", nil, nil)
	byPath := map[string]Rule{}
	for _, r := range spec.Deny {
		byPath[r.Path] = r
	}
	for _, rel := range []string{".zshrc", ".bashrc", ".profile", ".local/bin"} {
		r, ok := byPath[filepath.Join(home, rel)]
		if !ok {
			t.Errorf("no rule for ~/%s", rel)
			continue
		}
		if r.Mode != DenyWrite {
			t.Errorf("~/%s is %v, want DenyWrite — the shell must still READ it", rel, r.Mode)
		}
	}
	if r := byPath[filepath.Join(home, ".local/bin")]; !r.Tree {
		t.Error("~/.local/bin must be a tree rule")
	}
	if r := byPath[filepath.Join(home, ".config/autostart")]; r.OS != "linux" {
		t.Errorf("autostart should be linux-only, got OS %q", r.OS)
	}
	if r := byPath[filepath.Join(home, "Library/LaunchAgents")]; r.OS != "darwin" {
		t.Errorf("LaunchAgents should be darwin-only, got OS %q", r.OS)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("surface does not validate: %v", err)
	}
}

func TestDenyingDisplayAndWritesTo(t *testing.T) {
	t.Setenv("XAUTHORITY", "/tmp/xauth_test")
	spec := Spec{DenyPeerProcesses: true}.DenyingDisplay()
	paths := map[string]Rule{}
	for _, r := range spec.Deny {
		paths[r.Path] = r
	}
	if r, ok := paths["/tmp/.X11-unix"]; !ok || !r.Tree || r.OS != "linux" || r.Mode != DenyAll {
		t.Errorf("X11 socket directory rule wrong or missing: %+v", r)
	}
	if _, ok := paths["/tmp/xauth_test"]; !ok {
		t.Error("XAUTHORITY was not masked")
	}
	// A hostile XAUTHORITY must not become a mount argument.
	t.Setenv("XAUTHORITY", "/tmp/../etc/passwd")
	for _, r := range (Spec{}).DenyingDisplay().Deny {
		if strings.Contains(r.Path, "etc/passwd") {
			t.Fatalf("unsafe XAUTHORITY reached the deny list: %q", r.Path)
		}
	}

	// DenyingWritesTo: a path already under a sealed tree is not added twice;
	// a path outside the allowed roots is refused rather than rendered.
	home := homeDir()
	s := Surface("/tmp/d", "/tmp/r", nil, nil)
	n := len(s.Deny)
	s = s.DenyingWritesTo(filepath.Join(home, ".local/bin/akasha"), "binary")
	if len(s.Deny) != n {
		t.Error("binary under ~/.local/bin was added although the tree already seals it")
	}
	s = s.DenyingWritesTo("/opt/homebrew/Cellar/akasha/0.1/libexec/akasha", "binary")
	if len(s.Deny) != n+1 || s.Deny[n].Mode != DenyWrite {
		t.Error("a Homebrew keg path was not sealed")
	}
	s = s.DenyingWritesTo("/bin/akasha", "binary")
	if len(s.Deny) != n+1 {
		t.Error("a path outside the allowed roots was accepted")
	}
}

// Absent targets on the write side: a missing directory becomes an empty
// read-only one, a missing file is recorded as unenforced rather than
// aborting the launch, and the macOS renderer, being pattern-based, emits
// file-write* for both regardless.
func TestWriteSideRendersAbsentTargets(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.rc")
	os.WriteFile(present, []byte("x"), 0o600)
	absentFile := filepath.Join(dir, "absent.rc")
	absentDir := filepath.Join(dir, "autostart")
	spec := Spec{
		Deny: []Rule{
			{Path: present, Mode: DenyWrite, Why: "t"},
			{Path: absentFile, Mode: DenyWrite, Why: "t"},
			{Path: absentDir, Tree: true, Mode: DenyWrite, Why: "t"},
		},
		DenyPeerProcesses: true,
	}
	if !strings.HasPrefix(dir, "/tmp") && !strings.HasPrefix(dir, "/private") && !strings.HasPrefix(dir, "/var/folders") {
		t.Skipf("temp dir %s is outside the allowed roots", dir)
	}

	argv, plan, err := compile(spec, "/usr/bin/bwrap", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	// Mounts land on the RESOLVED path (/var is /private/var on macOS).
	resolve := func(p string) string { return mountTargets(p)[0] }
	present, absentDir = resolve(present), resolve(absentDir)
	if !strings.Contains(joined, "--ro-bind "+present+" "+present) {
		t.Errorf("present file not ro-bound:\n%s", joined)
	}
	if strings.Contains(joined, absentFile) {
		t.Errorf("absent file reached the argv (bwrap would abort the launch):\n%s", joined)
	}
	if !strings.Contains(joined, "--tmpfs "+absentDir) || !strings.Contains(joined, "--remount-ro "+absentDir) {
		t.Errorf("absent directory did not become an empty read-only tmpfs:\n%s", joined)
	}
	mech := map[string]Mechanism{}
	for _, d := range plan.Dispositions {
		mech[d.Path] = d.Mechanism
	}
	if mech[absentFile] != MechAbsent {
		t.Errorf("absent file disposition %q, want %q", mech[absentFile], MechAbsent)
	}
	if err := plan.Assert(spec); err != nil {
		t.Fatalf("plan does not assert: %v", err)
	}

	sbpl, err := renderSBPL(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{present, absentFile, absentDir} {
		if !strings.Contains(sbpl, "(deny file-write*") || !strings.Contains(sbpl, p) {
			t.Errorf("macOS profile is missing a file-write* deny for %s", p)
		}
	}
	if strings.Contains(sbpl, `(deny file-read* file-write* (literal "`+present) {
		t.Error("macOS profile denies READS of a write-side rule")
	}
}

// Run it for real: the write is refused, the read still works, and a socket
// inside a denied tree cannot be connected to.
func TestEnforceWriteSideAndDeniedSocket(t *testing.T) {
	requireSandbox(t)
	// Short path on purpose: a unix socket path is capped at ~104 bytes on
	// macOS, and t.TempDir is longer than that under /var/folders.
	dir, err := os.MkdirTemp("/tmp", "ak-ws-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	rc := filepath.Join(dir, "zshrc")
	os.WriteFile(rc, []byte("export OK=1\n"), 0o600)
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	sockDir := filepath.Join(dir, "X11-unix")
	os.MkdirAll(sockDir, 0o755)
	ln, err := net.Listen("unix", filepath.Join(sockDir, "X0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	spec := Spec{
		Deny: []Rule{
			{Path: rc, Mode: DenyWrite, Why: "rc"},
			{Path: bin, Tree: true, Mode: DenyWrite, Why: "bin"},
			{Path: sockDir, Tree: true, Mode: DenyAll, Why: "display"},
		},
		DenyPeerProcesses: true,
	}
	if err := spec.Validate(); err != nil {
		t.Skipf("temp dir outside allowed roots: %v", err)
	}
	script := `
cat ` + rc + ` >/dev/null && echo read-ok || echo read-FAIL
( echo evil >> ` + rc + ` ) 2>/dev/null && echo rc-WRITTEN || echo rc-sealed
( : > ` + bin + `/evil ) 2>/dev/null && echo bin-WRITTEN || echo bin-sealed
[ -S ` + sockDir + `/X0 ] && echo sock-VISIBLE || echo sock-masked
`
	out, _ := sh(t, spec, script)
	for _, want := range []string{"read-ok", "rc-sealed", "bin-sealed", "sock-masked"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if b, _ := os.ReadFile(rc); strings.Contains(string(b), "evil") {
		t.Error("the rc file was modified on the host")
	}
	if _, err := os.Stat(filepath.Join(bin, "evil")); err == nil {
		t.Error("a file was created in the sealed bin directory")
	}

	// And the self-test catches the same things: with the seal removed from
	// the spec but the probe plan built from the sealed one, the child must
	// report the write and the socket.
	plan, _ := planFor(spec)
	p := planProbe(spec, plan)
	if len(p.DenySockets) != 1 || len(p.DenyWritePaths) != 2 {
		t.Fatalf("probe plan did not pick up the socket and both write targets: %+v", p)
	}
	// A socket the spec allows back is a door, not a leak: `sandbox doctor`
	// allows the daemon socket back into the denied data directory, and the
	// probe must not then report that door as a failure.
	door := spec.AllowSocketPath(filepath.Join(sockDir, "X0"))
	if dp := planProbe(door, plan); len(dp.DenySockets) != 0 {
		t.Fatalf("an allowed-back socket was scheduled as a deny probe: %v", dp.DenySockets)
	}
}
