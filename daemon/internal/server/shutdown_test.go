package server_test

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// stoppableServer is newTestServer, but it also hands back the *Server so the
// stop path can be wired — which is the whole subject here.
func stoppableServer(t *testing.T) (*httptest.Server, *vault.Vault, *server.Server) {
	t.Helper()
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
	srv.SetPolicyEngine(policy.NewEngine(filepath.Join(dir, "policy.yaml")))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); auditL.Close(); vlt.Close() })
	return humanServer(t, ts, vlt), vlt, srv
}

// The daemon can be stopped over the socket, because until this existed the
// only clean stop was a signal somebody else had to send — which is why
// uninstall could ask systemd, be refused, and report a removal anyway.
func TestShutdownStopsTheDaemon(t *testing.T) {
	ts, _, srv := stoppableServer(t)
	stopped := make(chan struct{})
	srv.SetStopper(func() { close(stopped) })

	code, out := post(t, ts, "/shutdown", map[string]interface{}{}, "")
	if code != 200 {
		t.Fatalf("/shutdown as the human: got %d (%v)", code, out)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("/shutdown answered 200 but never triggered the stop — the exact shape of the bug")
	}
}

// An agent may not turn the credential broker off. Same rule as /vault/purge,
// and for the same reason: denying service to the thing that audits you is a
// capability worth withholding.
func TestShutdownIsHumanOnly(t *testing.T) {
	ts, vlt, srv := stoppableServer(t)
	called := false
	srv.SetStopper(func() { called = true })

	code, out := post(t, ts, "/shutdown", map[string]interface{}{}, agentKeyFor(t, vlt, "bot"))
	if code != 403 {
		t.Fatalf("an agent stopping the daemon: got %d, want 403 (%v)", code, out)
	}
	if called {
		t.Fatal("the stop ran anyway")
	}
}

// A server with no stop path must say so rather than answer 200 to a shutdown
// that will never happen — the failure mode this whole change is about.
func TestShutdownWithoutAStopPathSaysSo(t *testing.T) {
	ts, _, _ := stoppableServer(t)
	if code, _ := post(t, ts, "/shutdown", map[string]interface{}{}, ""); code != 501 {
		t.Fatalf("no stopper wired: got %d, want 501", code)
	}
}

func agentKeyFor(t *testing.T, vlt *vault.Vault, id string) string {
	t.Helper()
	_, key, err := vlt.CreateAgentKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
