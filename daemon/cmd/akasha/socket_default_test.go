package main

import (
	"path/filepath"
	"testing"
)

// A supervised run hands its child AKASHA_SOCKET, the run's private socket that
// is bound into the sandbox. Every CLI invocation inside the run — the git
// credential helper, credential_process — must dial that one, because the
// data-dir socket is masked and, under --no-network, so is loopback.
func TestDefaultSocketPathHonoursRunSocket(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("AKASHA_SOCKET", "")
	if got, want := defaultSocketPath(dir), filepath.Join(dir, "akasha.sock"); got != want {
		t.Fatalf("unset: got %q, want %q", got, want)
	}

	run := filepath.Join(t.TempDir(), "akasha-run-1", "akasha.sock")
	t.Setenv("AKASHA_SOCKET", run)
	if got := defaultSocketPath(dir); got != run {
		t.Fatalf("with AKASHA_SOCKET: got %q, want %q (negative control above passed, so the env is what changed it)", got, run)
	}
}
