package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/clikey"
	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// escrowDaemon starts a real daemon on a unix socket and points the CLI's own
// globals (dbPath, socketPath) at it, so a test can drive the cobra commands
// exactly as a shell would. Returns the socket path and the data dir.
func escrowDaemon(t *testing.T) (string, string) {
	t.Helper()
	// The developer's own shell may carry an injected AKASHA_AGENT_ID/KEY (from
	// `akasha setup` env-ownership); the fresh test vault would reject the key.
	// Both must be cleared: a session with an agent ID but no key is treated as
	// an agent that dropped its key, and the CLI refuses to fall back to the
	// human identity there rather than quietly upgrading it (see callerKey).
	t.Setenv("AKASHA_AGENT_KEY", "")
	t.Setenv("AKASHA_AGENT_ID", "")

	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(classifier.New(nil), vlt, auditL)

	// The socket does NOT go in t.TempDir(). A unix socket path must fit in the
	// kernel's fixed sockaddr_un field (104 bytes on darwin), and macOS temp
	// dirs are ~90 characters before the test name and a random suffix are
	// added — putting this test right on the boundary, so it passed or failed
	// depending on how many digits Go happened to pick. Bind under /tmp so the
	// path is short by construction.
	sockDir, err := os.MkdirTemp("/tmp", "akasha-sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "s.sock")

	// Surface the listen error instead of dropping it: without this the only
	// symptom is the poll below timing out with "socket never came up", which
	// says nothing about why.
	listenErr := make(chan error, 1)
	go func() { listenErr <- srv.ListenUnix(sock) }()
	t.Cleanup(func() {
		select {
		case err := <-listenErr:
			if err != nil {
				t.Errorf("ListenUnix: %v", err)
			}
		default:
		}
	})
	t.Cleanup(func() { auditL.Close(); vlt.Close() })

	// Provision this vault's CLI key, exactly as `akasha start` does, and point
	// the CLI's dbPath at it so callerKey() finds it. The daemon refuses
	// unauthenticated callers, so without this the client below has no identity
	// to present — and leaving dbPath at its default would make it offer the
	// developer's real key to a scratch vault that has never seen it.
	oldDB, oldSock := dbPath, socketPath
	dbPath = filepath.Join(dir, "vault.db")
	socketPath = sock
	t.Cleanup(func() { dbPath, socketPath = oldDB, oldSock })
	if _, err := clikey.Ensure(vlt, clikey.Path(dbPath)); err != nil {
		t.Fatalf("provision cli key: %v", err)
	}

	// Wait for the socket to accept.
	deadline := 50
	var lastErr error
	for ; deadline > 0; deadline-- {
		if _, lastErr = (daemonVault{sock: sock}).ListLabels("escrow:"); lastErr == nil {
			break
		}
	}
	if deadline == 0 {
		// Report the reason. This loop used to discard it, so an auth failure
		// looked identical to a socket that never bound.
		t.Fatalf("daemon socket never came up: %v", lastErr)
	}
	return sock, dir
}

// End-to-end over the real wire: daemonVault speaks hand-rolled HTTP/1.0 to a
// unix socket, so exercise protect/restore against a real server rather than
// trusting the JSON shapes.
func TestProtectRestoreOverSocket(t *testing.T) {
	sock, dir := escrowDaemon(t)
	v := daemonVault{sock: sock}

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
