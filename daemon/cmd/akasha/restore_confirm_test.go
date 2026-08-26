package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
)

// `akasha protect` was undone by an unconfirmed `akasha restore`.
//
// The stub left on disk NAMES the command that reverses it, in a comment aimed
// at the human — and an agent that read the stub ran it. Restore exited 0 with
// no confirmation, put the plaintext back on disk, and left nothing behind to
// notice. The daemon now refuses to hand an escrowed original to an agent
// identity at all (see internal/server's escrow gate), but the CLI half stands
// on its own: putting a protected credential back is a security-relevant act,
// and it should happen because the owner said so, not because something typed
// the command that was printed for them.
func TestRestoreRefusesWithoutConfirmation(t *testing.T) {
	sock, dir := escrowDaemon(t)
	v := daemonVault{sock: sock}

	const creds = "[default]\naws_secret_access_key = sekrit\n"
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte(creds), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := escrow.Protect(v, path); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Stdin is a pipe with the write end closed: not a terminal, which is the
	// non-interactive case that must fail closed. Whatever the test binary was
	// handed would otherwise decide the outcome — and against a real TTY the
	// prompt would block the suite forever.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })

	restoreYes, restoreAll = false, false
	t.Cleanup(func() { restoreYes, restoreAll = false, false })

	if err := restoreCmd.RunE(restoreCmd, []string{path}); err != nil {
		t.Fatalf("an aborted restore is not an error: %v", err)
	}
	if got, _ := os.ReadFile(path); !escrow.IsStub(got) {
		t.Fatal("restore rewrote the plaintext with no confirmation")
	}

	// --yes is the owner saying it deliberately, and still works.
	restoreYes = true
	if err := restoreCmd.RunE(restoreCmd, []string{path}); err != nil {
		t.Fatalf("confirmed restore: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != creds {
		t.Fatalf("confirmed restore did not put the original back: %q", got)
	}
}

// --all is the wider blast radius, so it must not be the looser path.
func TestRestoreAllRefusesWithoutConfirmation(t *testing.T) {
	sock, dir := escrowDaemon(t)
	v := daemonVault{sock: sock}

	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte("[default]\nkey = sekrit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := escrow.Protect(v, path); err != nil {
		t.Fatalf("protect: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })

	restoreYes, restoreAll = false, true
	t.Cleanup(func() { restoreYes, restoreAll = false, false })

	if err := restoreCmd.RunE(restoreCmd, nil); err != nil {
		t.Fatalf("an aborted restore is not an error: %v", err)
	}
	if got, _ := os.ReadFile(path); !escrow.IsStub(got) {
		t.Fatal("restore --all rewrote the plaintext with no confirmation")
	}
}
