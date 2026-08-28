package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These drive the REAL Surface() through the real sandbox, which nothing did
// before — and that gap is why four separate causes of the same bug reached
// users with CI green the whole time.
//
// specFor, which every other enforcement test uses, builds a Spec with ONE rule
// pointing at a temp directory. That exercises the kernel, but not the deny set
// akasha actually ships: not the macOS-only paths rendered on Linux, not the
// docker socket, not the session bus, not a symlinked home. Every one of those
// broke the launch for ordinary users while `go test ./...` passed.
//
// The two properties are checked separately and both matter, because the fixes
// have traded one for the other twice: a rule that skipped what it could not
// mount made the launch work and turned fail-closed into fail-open, and a rule
// that mounted everything was airtight and could not start.

// surfaceHome builds a home directory of the shape a real one has, and returns
// the resolved path — the renderer mounts symlink-resolved targets, and on many
// systems a temp dir is reached through one.
func surfaceHome(t *testing.T, withOptionalFiles bool) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home+"/.akasha/templates.dist", 0700); err != nil {
		t.Fatal(err)
	}
	if withOptionalFiles {
		if err := os.MkdirAll(home+"/.ssh", 0700); err != nil {
			t.Fatal(err)
		}
		for path, body := range map[string]string{
			home + "/.ssh/known_hosts": "github.com ssh-rsa AAAA\n",
			home + "/.ssh/config":      "Host github.com\n  User git\n",
			home + "/.gitconfig":       "[user]\n\tname = Test\n",
		} {
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return home
}

// The shipped deny set must produce a sandbox that STARTS, on a machine that
// looks like a developer's rather than like a test fixture.
//
// Both halves of the matrix are real states: ssh writes known_hosts on first
// connect, so "present" is the common case — and it was the failing one, because
// the read-only seal went on before the allow-backs could mount into it. The
// absent case is a fresh container, which failed for a different reason.
func TestEnforceRealSurfaceLaunches(t *testing.T) {
	requireSandbox(t)

	for _, tc := range []struct {
		name     string
		optional bool
	}{
		{"optional home files present", true},
		{"bare home", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := surfaceHome(t, tc.optional)
			t.Setenv("HOME", home)
			runDir := t.TempDir()

			spec := Surface(home+"/.akasha", runDir, nil, nil)
			out, err := sh(t, spec, "echo sandbox-ok")
			if err != nil {
				t.Fatalf("the shipped surface could not start a sandbox: %v\n%s", err, out)
			}
			if !strings.Contains(out, "sandbox-ok") {
				t.Fatalf("sandbox started but the command did not run: %q", out)
			}
		})
	}
}

// …and it must still DENY. A rule that skips what it cannot mount makes the
// launch work by leaving holes, so the launch test above is only half a claim.
//
// The case that matters is a denied file that does not exist when the sandbox is
// built: the child can create it a moment later, and if the mask was skipped it
// can then read it back. ~/.netrc, ~/.git-credentials, ~/.pgpass and the key
// backup were all readable this way, from inside, once something made them.
func TestEnforceRealSurfaceMasksFilesCreatedMidRun(t *testing.T) {
	requireSandbox(t)

	home := surfaceHome(t, true)
	t.Setenv("HOME", home)
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)

	for _, rel := range []string{".netrc", ".git-credentials", ".pgpass"} {
		t.Run(rel, func(t *testing.T) {
			// Created INSIDE the sandbox, after every mount is in place.
			script := "echo CANARY-" + rel + " > $HOME/" + rel + " 2>/dev/null; cat $HOME/" + rel + " 2>/dev/null"
			out, _ := sh(t, spec, script)
			if strings.Contains(out, "CANARY-") {
				t.Errorf("%s was readable from inside after being created mid-run — "+
					"the mask was skipped because the file did not exist at launch:\n%s", rel, out)
			}
		})
	}
}

// The doors the deny set opens on purpose must still be open, or the sandbox is
// airtight and useless — which is the other way these fixes have gone wrong.
func TestEnforceRealSurfaceKeepsItsDoorsOpen(t *testing.T) {
	requireSandbox(t)

	home := surfaceHome(t, true)
	t.Setenv("HOME", home)
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)

	// known_hosts is allowed back inside a denied ~/.ssh.
	out, _ := sh(t, spec, "cat $HOME/.ssh/known_hosts 2>&1")
	if !strings.Contains(out, "ssh-rsa") {
		t.Errorf("~/.ssh/known_hosts is allowed back but was not readable inside: %q", out)
	}

	// The provider templates are allowed back inside a denied ~/.akasha, or the
	// broker cannot resolve anything from within a run.
	if err := os.WriteFile(home+"/.akasha/templates.dist/marker", []byte("tpl\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _ = sh(t, spec, "cat $HOME/.akasha/templates.dist/marker 2>&1")
	if !strings.Contains(out, "tpl") {
		t.Errorf("the templates door is shut, so a brokered call inside a run would find no provider: %q", out)
	}
}

// And the thing the whole surface exists to hide.
func TestEnforceRealSurfaceHidesTheVault(t *testing.T) {
	requireSandbox(t)

	home := surfaceHome(t, true)
	t.Setenv("HOME", home)
	if err := os.WriteFile(home+"/.akasha/vault.db", []byte("SQLite format 3\x00VAULT-CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)

	out, _ := sh(t, spec, "cat $HOME/.akasha/vault.db 2>&1")
	if strings.Contains(out, "VAULT-CANARY") {
		t.Fatalf("the vault was readable from inside the sandbox:\n%s", out)
	}
	out, _ = sh(t, spec, "echo x > $HOME/.akasha/probe 2>&1 && echo WROTE || echo denied")
	if strings.Contains(out, "WROTE") {
		t.Errorf("the akasha data directory was writable from inside: %q", out)
	}
}
