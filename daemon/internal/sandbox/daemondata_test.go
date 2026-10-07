package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func denies(s Spec, path string, tree bool) bool {
	for _, r := range s.Deny {
		if r.Path == path && r.Tree == tree && r.Mode == DenyAll {
			return true
		}
	}
	return false
}

// A relocated vault is masked as an island, and the files inside it need no
// rules of their own.
func TestDaemonDataRelocatedDirIsAnIsland(t *testing.T) {
	t.Setenv("HOME", "/Users/me")
	dir := "/Users/me/akasha-probe"
	s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
		DenyingDaemonData(dir, "/Users/me/src/app", dir+"/vault.db", dir+"/cli.key", dir+"/akasha.sock")
	if !denies(s, dir, true) {
		t.Fatalf("the relocated data dir is not masked:\n%+v", s.Deny)
	}
	if denies(s, dir+"/cli.key", false) {
		t.Fatal("a file inside the masked island got a redundant rule of its own")
	}
}

// The default layout is already Surface's island: nothing is added.
func TestDaemonDataDefaultLayoutIsANoop(t *testing.T) {
	t.Setenv("HOME", "/Users/me")
	base := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil)
	s := base.DenyingDaemonData("/Users/me/.akasha", "/Users/me/src/app",
		"/Users/me/.akasha/vault.db", "/Users/me/.akasha/cli.key", "/Users/me/.akasha/akasha.sock")
	if len(s.Deny) != len(base.Deny) {
		t.Fatalf("default layout added %d rules", len(s.Deny)-len(base.Deny))
	}
}

// Where masking the directory would take the agent's work with it, only the
// named files are masked — cli.key first among them.
func TestDaemonDataNeverMasksHomeTopLevelOrWorkDir(t *testing.T) {
	t.Setenv("HOME", "/Users/me")
	for _, tc := range []struct{ name, dir, work string }{
		{"home itself", "/Users/me", "/Users/me/src/app"},
		{"top-level", "/Users", "/Users/me/src/app"},
		{"above the work dir", "/Users/me/src", "/Users/me/src/app"},
		{"is the work dir", "/Users/me/src/app", "/Users/me/src/app"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.dir + "/cli.key"
			s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
				DenyingDaemonData(tc.dir, tc.work, tc.dir+"/vault.db", key)
			if denies(s, tc.dir, true) {
				t.Fatalf("%s was masked whole", tc.dir)
			}
			if !denies(s, key, false) {
				t.Fatalf("cli.key at %s is not masked", key)
			}
		})
	}
}

// The renderer carries the relocated island on both platforms.
func TestDaemonDataRendersOnBothPlatforms(t *testing.T) {
	t.Setenv("HOME", "/Users/me")
	dir := "/Users/me/akasha-probe"
	s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
		DenyingDaemonData(dir, "/Users/me/src/app", dir+"/cli.key")
	if p := darwinProfile(t, s); !strings.Contains(p, `(deny file-read* file-write* (subpath "/Users/me/akasha-probe"))`) {
		t.Fatalf("darwin profile does not mask the relocated dir:\n%s", p)
	}
	argv, err := DescribeFor("linux", s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(argv, dir) {
		t.Fatalf("linux plan does not mention the relocated dir:\n%s", argv)
	}
}

// The real backend: a relocated cli.key is not readable from inside.
func TestEnforceRelocatedCLIKeyIsHidden(t *testing.T) {
	requireSandbox(t)
	work := t.TempDir()
	dir := t.TempDir()
	key := filepath.Join(dir, "cli.key")
	if err := os.WriteFile(key, []byte("CANARY-CLI-KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := specFor(t, t.TempDir()).DenyingDaemonData(dir, work, key)
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	out, _ := sh(t, spec, "cat "+key+" 2>&1")
	if strings.Contains(out, "CANARY-CLI-KEY") {
		t.Fatalf("the relocated cli.key was readable inside the sandbox: %q", out)
	}
}

// A vault outside the roots the sandbox can mask is reported, so the caller
// can refuse instead of launching with it exposed.
func TestDaemonDataUnmaskableIsReported(t *testing.T) {
	if Maskable("/srv/akasha/cli.key") == nil {
		t.Fatal("a path the renderer will never mask was reported maskable")
	}
	if err := Maskable("/Users/me/akasha-probe/cli.key"); err != nil {
		t.Fatalf("an ordinary relocated vault was reported unmaskable: %v", err)
	}
}
