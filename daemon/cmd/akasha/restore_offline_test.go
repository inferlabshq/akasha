package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// `restore --offline` opens the vault directly, for when the daemon will not
// start. The stub names this command as the way back, so without it "the daemon
// is broken" also means "I cannot get my own file", which makes that promise
// false exactly when it matters.
//
// It deliberately reopens a narrower version of a path that was closed: until
// recently `akasha uninstall` reached the same envelopes through escrow.Direct
// with no prompt, no agent check and no audit record. Three properties are what
// make the narrow version acceptable, and each has an assertion here.
func TestRestoreOfflineIsHumanOnlyConfirmedAndAudited(t *testing.T) {
	stage := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home)
		dataDir := filepath.Join(home, ".akasha")
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			t.Fatal(err)
		}

		od, ol, os_ := dbPath, logPath, socketPath
		t.Cleanup(func() { dbPath, logPath, socketPath = od, ol, os_ })
		dbPath = filepath.Join(dataDir, "vault.db")
		logPath = filepath.Join(dataDir, "audit.log")
		// Deliberately unreachable: the whole point is that no daemon is here.
		socketPath = filepath.Join(dataDir, "nonexistent.sock")

		oy, oo, oa := restoreYes, restoreOffline, restoreAll
		t.Cleanup(func() { restoreYes, restoreOffline, restoreAll = oy, oo, oa })

		v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true})
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()
		secretFile := filepath.Join(home, "secrets.env")
		if err := os.WriteFile(secretFile, []byte("API_TOKEN=only-copy\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := escrow.Protect(escrow.Direct{Vault: v}, secretFile); err != nil {
			t.Fatal(err)
		}
		return secretFile
	}

	// PROPERTY 1: an agent session is refused, offline or not. Offline drops the
	// daemon's gate, so this environment check is the only one left.
	t.Run("refuses an agent session", func(t *testing.T) {
		secretFile := stage(t)
		t.Setenv("AKASHA_AGENT_ID", "claude-code")
		restoreOffline, restoreYes = true, true

		if err := restoreCmd.RunE(restoreCmd, []string{secretFile}); err == nil {
			t.Fatal("offline restore ran from an agent session")
		}
		if got, _ := os.ReadFile(secretFile); !escrow.IsStub(got) {
			t.Error("ESCROW BYPASS: the plaintext was written despite the refusal")
		}
	})

	// PROPERTY 2: --yes does not buy a way past the terminal on this path.
	// Offline has no daemon gate, so the terminal is the only remaining evidence
	// a human is here. In `go test` stdin is not a character device, so
	// confirmEscrow declines — which is the non-interactive case this asserts.
	t.Run("--yes does not skip the prompt offline", func(t *testing.T) {
		secretFile := stage(t)
		t.Setenv("AKASHA_AGENT_ID", "")
		t.Setenv("AKASHA_AGENT_KEY", "")
		restoreOffline, restoreYes = true, true

		out := captureOut(t, func() {
			if err := restoreCmd.RunE(restoreCmd, []string{secretFile}); err != nil {
				t.Fatalf("expected a clean abort, got: %v", err)
			}
		})
		if got, _ := os.ReadFile(secretFile); !escrow.IsStub(got) {
			t.Error("--yes skipped the confirmation on the offline path")
		}
		if !strings.Contains(out, "does not apply to --offline") {
			t.Errorf("the abort should say why --yes did not apply:\n%s", out)
		}
	})

	// PROPERTY 3: the daemon path still honours --yes. Without this, the test
	// above would pass just as happily against a command that ignored --yes
	// everywhere.
	t.Run("the daemon path still honours --yes", func(t *testing.T) {
		stage(t)
		t.Setenv("AKASHA_AGENT_ID", "")
		t.Setenv("AKASHA_AGENT_KEY", "")
		restoreOffline, restoreYes, restoreAll = false, true, true

		// No daemon is listening, so this fails at the transport rather than at
		// the prompt — which is the distinction being asserted.
		err := restoreCmd.RunE(restoreCmd, nil)
		if err == nil {
			t.Skip("unexpected success without a daemon; nothing to distinguish")
		}
		if strings.Contains(err.Error(), "does not apply to --offline") {
			t.Error("the daemon path refused --yes, which it should honour")
		}
	})
}

// PROPERTY 4: --offline refuses while a daemon is answering, because opening
// the vault directly then would fork the audit chain against the daemon's own
// writer. The refusal must land BEFORE the vault is opened and the file
// rewritten, and it must name the daemon route as the fix.
func TestRestoreOfflineRefusesWhileDaemonIsUp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AKASHA_AGENT_ID", "")
	t.Setenv("AKASHA_AGENT_KEY", "")
	dataDir := filepath.Join(home, ".akasha")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}

	od, ol, os_ := dbPath, logPath, socketPath
	oy, oo, oa := restoreYes, restoreOffline, restoreAll
	t.Cleanup(func() {
		dbPath, logPath, socketPath = od, ol, os_
		restoreYes, restoreOffline, restoreAll = oy, oo, oa
	})
	dbPath = filepath.Join(dataDir, "vault.db")
	logPath = filepath.Join(dataDir, "audit.log")

	// Stand up a plaintext original and escrow it, so a restore has something to
	// do — a refusal that fired only on an empty vault would prove nothing.
	v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(home, "secrets.env")
	if err := os.WriteFile(secretFile, []byte("API_TOKEN=only-copy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := escrow.Protect(escrow.Direct{Vault: v}, secretFile); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// A listener is all DaemonReachable tests — it dials and closes. It need not
	// speak HTTP: the refusal is meant to fire before any request is made. The
	// socket lives in a short /tmp dir, not under t.TempDir(): a macOS temp path
	// already exceeds the 104-byte sun_path limit, so binding there fails for a
	// reason unrelated to what this test is about.
	sockDir, err := os.MkdirTemp("/tmp", "akrst")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	socketPath = filepath.Join(sockDir, "a.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	restoreOffline, restoreYes, restoreAll = true, true, false
	err = restoreCmd.RunE(restoreCmd, []string{secretFile})
	if err == nil {
		t.Fatal("--offline restored while a daemon was answering; the audit chain would fork")
	}
	if !strings.Contains(err.Error(), "daemon is running") || !strings.Contains(err.Error(), "akasha restore") {
		t.Errorf("the refusal must name the daemon route as the fix, got: %v", err)
	}
	// The plaintext must NOT have been written: the refusal is the whole point.
	if got, _ := os.ReadFile(secretFile); !escrow.IsStub(got) {
		t.Error("the file was restored despite the refusal — the check landed too late")
	}
}

// captureOut collects stdout for the duration of fn.
func captureOut(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// The audit record is the justification for the flag existing, so it gets its
// own assertion rather than being assumed.
//
// The daemon writes a record for every retrieval, and --offline exists precisely
// by not going through it. Without this append, the one honest cost of the flag
// would be unrecorded, and protect.go's claim that every access is "audited"
// would be false in a second place.
func TestOfflineRestoreWritesAnAuditRecord(t *testing.T) {
	dir := t.TempDir()
	ol, oo := logPath, restoreOffline
	t.Cleanup(func() { logPath, restoreOffline = ol, oo })
	logPath = filepath.Join(dir, "audit.log")
	restoreOffline = true

	auditOfflineRestore("/home/dev/secrets.env")

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no audit log was written: %v", err)
	}
	for _, want := range []string{"RETRIEVED", "akasha_restore_offline", "/home/dev/secrets.env"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the record should contain %q:\n%s", want, body)
		}
	}

	// And the daemon path must NOT write this record — it has its own, written
	// by the daemon, and a duplicate would misreport one access as two.
	restoreOffline = false
	before := len(body)
	auditOfflineRestore("/home/dev/other.env")
	after, _ := os.ReadFile(logPath)
	if len(after) != before {
		t.Error("the daemon path wrote an offline audit record, duplicating the daemon's own")
	}
}

// An unwritable log must not cost the owner their file — but it must not be
// silent either.
func TestOfflineRestoreSaysSoWhenItCannotAudit(t *testing.T) {
	ol, oo := logPath, restoreOffline
	t.Cleanup(func() { logPath, restoreOffline = ol, oo })
	logPath = filepath.Join(t.TempDir(), "no-such-dir", "audit.log")
	restoreOffline = true

	r, w, _ := os.Pipe()
	oldErr := os.Stderr
	os.Stderr = w
	auditOfflineRestore("/home/dev/secrets.env")
	w.Close()
	os.Stderr = oldErr
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	got := string(buf[:n])

	if !strings.Contains(got, "could NOT write an audit record") {
		t.Errorf("an unwritable audit log must be announced, got: %q", got)
	}
	if !strings.Contains(got, "unrecorded") {
		t.Errorf("the warning should say the access is unrecorded, got: %q", got)
	}
}
