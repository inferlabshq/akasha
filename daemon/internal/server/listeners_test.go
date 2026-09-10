package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// rawServer builds a *Server backed by a temp vault (white-box, so tests can
// drive unexported serve/listenTCP).
func rawServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditL.Close(); vlt.Close() })
	return New(classifier.New(nil), vlt, auditL)
}

func waitHealthy(t *testing.T, client *http.Client, url string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not become healthy")
}

// serve + Shutdown over a TCP listener on an ephemeral port.
func TestServeAndShutdown(t *testing.T) {
	s := rawServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.serve(ln, s.mux) }()

	url := "http://" + ln.Addr().String() + "/health"
	waitHealthy(t, http.DefaultClient, url)

	s.Shutdown(context.Background())
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after Shutdown")
	}
}

// GUARANTEE: once Shutdown has run, a listener that starts afterwards serves
// nothing.
//
// serve() used to register its *http.Server and only then begin serving, so a
// Shutdown landing in between walked a list the listener was not in and never
// stopped it. In the daemon that listener is one of the goroutines startCmd
// waits for before it returns, so the process parks forever — still answering
// on the socket and the loopback port, still handing out credentials — with
// SIGTERM, SIGINT and SIGHUP already trapped by its own handler. Only SIGKILL
// ends it, and SIGKILL skips the vault Close that folds the write-ahead log
// into vault.db.
func TestServeAfterShutdownServesNothing(t *testing.T) {
	s := rawServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	// The stop arrives while the listener goroutine has not reached serve yet.
	s.Shutdown(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.serve(ln, s.mux) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v, want nil for a listener that never started", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve kept running after Shutdown — the daemon would wait on this listener " +
			"forever with its termination signals already trapped, so nothing but SIGKILL " +
			"could stop it and the vault would never be closed")
	}

	if conn, derr := net.DialTimeout("tcp", addr, time.Second); derr == nil {
		conn.Close()
		t.Fatal("the daemon still accepts connections after Shutdown")
	}
}

// ListenUnix happy path + error path.
func TestListenUnix(t *testing.T) {
	s := rawServer(t)
	sock := filepath.Join(t.TempDir(), "a.sock")
	go s.ListenUnix(sock)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", sock)
		},
	}}
	waitHealthy(t, client, "http://akasha/health")
	s.Shutdown(context.Background())

	// error: a socket path under a non-existent directory can't be bound.
	if err := s.ListenUnix("/no/such/dir/x.sock"); err == nil {
		t.Fatal("expected error binding unix socket in missing dir")
	}
}

// listenTCP error path (port already in use) + ListenHTTP wrapper.
func TestListenTCPErrorAndWrapper(t *testing.T) {
	s := rawServer(t)

	// Occupy an ephemeral port, then point listenTCP at it to force a bind error.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if err := s.listenTCP(blocker.Addr().String()); err == nil {
		t.Fatal("expected bind error on occupied port")
	}

	// listenTCP success path on an ephemeral port (bind ok → log → serve).
	go s.listenTCP("127.0.0.1:0")
	time.Sleep(50 * time.Millisecond)

	// Cover the ListenHTTP() wrapper. It binds the default port; whether that
	// succeeds or fails (a daemon may hold it), the wrapper statement runs.
	go s.ListenHTTP()
	time.Sleep(50 * time.Millisecond)
	s.Shutdown(context.Background())
}

// GUARANTEE: a bind failure is reported by Bind*, BEFORE anything serves.
//
// `akasha start` spawned the listeners as goroutines and printed "daemon
// started" the instant they were spawned, so a bind that then failed — the
// machine-wide port already held by another user's daemon, or a socket path
// over the OS limit — reached the screen as an error line AFTER a success line
// it contradicted, and the process could still exit 0. The banner is now
// gated on Bind* returning nil, so these have to fail SYNCHRONOUSLY, before a
// serve, or the gate proves nothing.
func TestBindReportsFailureBeforeServing(t *testing.T) {
	s := rawServer(t)

	// A path over the sun_path limit: BindUnix returns the sized error and
	// creates no listener, rather than a goroutine discovering it later.
	// (A live socket is deliberately NOT this case — BindUnix removes and
	// rebinds a stale path, which is why startCmd dials first; see that guard.
	// The BindUnix→ServeUnix happy path is covered by TestListenUnix, which
	// now routes through the split.)
	long := strings.Repeat("x", MaxUnixSocketPath+1)
	if ln, err := s.BindUnix(long); err == nil {
		ln.Close()
		t.Fatalf("BindUnix accepted a %d-byte path, over the %d-byte limit", len(long), MaxUnixSocketPath)
	}

	// BindHTTP on a port something already holds returns the error rather than a
	// serving listener — the cross-user port conflict that used to surface only
	// after "daemon started". Hold the default port ourselves; if a daemon on
	// this host already holds it, that is the same condition and BindHTTP must
	// still fail.
	addr := fmt.Sprintf("127.0.0.1:%d", HTTPPort)
	if blocker, err := net.Listen("tcp", addr); err == nil {
		defer blocker.Close()
	}
	if ln, err := s.BindHTTP(); err == nil {
		ln.Close()
		t.Fatalf("BindHTTP bound port %d while another listener held it", HTTPPort)
	}
}

// serve must return the underlying error when the listener breaks outside of a
// graceful Shutdown (i.e. not http.ErrServerClosed).
func TestServeReturnsErrorOnBrokenListener(t *testing.T) {
	s := rawServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.serve(ln, s.mux) }()
	waitHealthy(t, http.DefaultClient, "http://"+ln.Addr().String()+"/health")

	ln.Close() // break the listener directly (not via Shutdown)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve should return the listener error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after listener closed")
	}
}
