package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// daemonStub points the CLI at a unix socket that answers every request with
// one status and body, or at a path nothing listens on when body is "".
func daemonStub(t *testing.T, code int, body string) {
	t.Helper()
	// Not t.TempDir(): its path is long enough to break the sun_path limit.
	dir, err := os.MkdirTemp("", "ak")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	for _, k := range []string{"AKASHA_AGENT_ID", "AKASHA_AGENT_KEY", "AKASHA_HTTP"} {
		t.Setenv(k, "")
	}
	old := socketPath
	socketPath = filepath.Join(dir, "a.sock")
	t.Cleanup(func() { socketPath = old })
	if body == "" {
		return
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, code)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

// A policy denial reached credential_process as "daemon not reachable (is
// `akasha start` running?): denied by policy": the daemon had answered, and the
// advice was to restart it.
func TestDenialIsNotReportedAsAnUnreachableDaemon(t *testing.T) {
	daemonStub(t, http.StatusForbidden, "denied by policy: policy rule 1")
	_, err := resolveCreds("aws", "default")
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	for _, want := range []string{"denied by policy: policy rule 1", "aws:default"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q: %v", want, err)
		}
	}
	for _, not := range []string{"not reachable", "akasha start"} {
		if strings.Contains(err.Error(), not) {
			t.Errorf("a denial says %q: %v", not, err)
		}
	}
	if _, err := describableTargets(); err == nil || strings.Contains(err.Error(), "not reachable") {
		t.Errorf("whoami reports a refusal as unreachable: %v", err)
	}
}

// The advice must survive where it is right: nothing answered.
func TestSilentDaemonStillSaysHowToStartIt(t *testing.T) {
	daemonStub(t, 0, "")
	_, err := resolveCreds("aws", "default")
	if err == nil || !strings.Contains(err.Error(), "not reachable") || !strings.Contains(err.Error(), "akasha start") {
		t.Errorf("lost the unreachable advice: %v", err)
	}
}
