package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/internal/audit"
	"github.com/inferlabshq/akasha/internal/classifier"
	"github.com/inferlabshq/akasha/internal/escrow"
	"github.com/inferlabshq/akasha/internal/server"
	"github.com/inferlabshq/akasha/internal/vault"
)

// End-to-end over the real wire: daemonVault speaks hand-rolled HTTP/1.0 to a
// unix socket, so exercise protect/restore against a real server rather than
// trusting the JSON shapes.
func TestProtectRestoreOverSocket(t *testing.T) {
	// The developer's own shell may carry an injected AKASHA_AGENT_KEY (from
	// `akasha setup` env-ownership); the fresh test vault would reject it.
	t.Setenv("AKASHA_AGENT_KEY", "")

	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(classifier.New(nil), vlt, auditL)
	sock := filepath.Join(dir, "akasha.sock")
	go srv.ListenUnix(sock)
	t.Cleanup(func() { auditL.Close(); vlt.Close() })

	// Wait for the socket to accept.
	v := daemonVault{sock: sock}
	deadline := 50
	for ; deadline > 0; deadline-- {
		if _, err := v.ListLabels("escrow:"); err == nil {
			break
		}
	}
	if deadline == 0 {
		t.Fatal("daemon socket never came up")
	}

	const creds = "[default]\naws_secret_access_key = sekrit\n"
	path := filepath.Join(dir, "credentials")
	os.WriteFile(path, []byte(creds), 0640)

	if _, err := escrow.Protect(v, path); err != nil {
		t.Fatalf("Protect over socket: %v", err)
	}
	stub, _ := os.ReadFile(path)
	if !escrow.IsStub(stub) {
		t.Fatal("expected stub on disk")
	}

	paths, err := escrow.List(v)
	if err != nil || len(paths) != 1 || paths[0] != path {
		t.Fatalf("List over socket: %v %v", paths, err)
	}

	if err := escrow.Restore(v, path); err != nil {
		t.Fatalf("Restore over socket: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte(creds)) {
		t.Fatalf("restore not verbatim: %q", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0640 {
		t.Fatalf("restored mode %v, want 0640", fi.Mode().Perm())
	}
}
