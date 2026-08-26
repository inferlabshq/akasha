package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// countingDaemon listens on a unix socket and counts connections, which is how
// a test proves a write was never ATTEMPTED — an error from an undialable
// socket looks the same whether the caller declined or tried and failed.
func countingDaemon(t *testing.T) *int32 {
	t.Helper()
	// Short path: a unix socket under the macOS temp dir t.TempDir() hands out
	// exceeds the 104-byte sun_path limit.
	dir, err := os.MkdirTemp("/tmp", "akdisc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var n int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&n, 1)
			c.Close()
		}
	}()
	old := socketPath
	socketPath = ln.Addr().String()
	t.Cleanup(func() { socketPath = old; ln.Close() })
	return &n
}

// notATerminal points os.Stdin at a pipe, so the non-interactive branch is
// taken whether or not the test binary was started from a terminal.
func notATerminal(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close(); w.Close() })
}

// Piping anything into `akasha discover` used to skip the prompt and vault
// everything — "no" included: `echo n | akasha discover all` stored 32
// credentials on the test machine. The trigger is not the pipe, it is any stdin
// that is not a tty: CI, a Makefile, `curl | sh`, `docker run` without -t, and
// an agent running `akasha`. Consent has to be spelled, and --yes spells it.
func TestReviewAndVaultRefusesWithoutTerminalOrYes(t *testing.T) {
	dialled := countingDaemon(t)
	notATerminal(t)
	t.Cleanup(func(d bool) func() { return func() { discoverDryRun = d } }(discoverDryRun))
	discoverDryRun = false

	err := reviewAndVault([]template.Finding{
		{Provider: "aws", Instance: "default", Fields: map[string]string{"access_key_id": "AKIA1"}, Source: "~/.aws/credentials"},
	}, false)
	if err == nil {
		t.Fatal("a non-interactive run must not report success over an unchanged vault")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("the error must name the flag that says yes, got: %v", err)
	}
	if n := atomic.LoadInt32(dialled); n != 0 {
		t.Fatalf("the daemon was contacted %d time(s) — something was vaulted", n)
	}
}

// The escape hatch has to keep working, or the fix above just breaks every
// unattended install instead.
func TestReviewAndVaultYesStillVaults(t *testing.T) {
	dialled := countingDaemon(t)
	notATerminal(t)
	t.Cleanup(func(d bool) func() { return func() { discoverDryRun = d } }(discoverDryRun))
	discoverDryRun = false

	// The socket accepts and hangs up, so vaulting fails — an attempt is what is
	// being tested, not a round trip.
	_ = reviewAndVault([]template.Finding{
		{Provider: "aws", Instance: "default", Fields: map[string]string{"access_key_id": "AKIA1"}, Source: "~/.aws/credentials"},
	}, true)
	if n := atomic.LoadInt32(dialled); n == 0 {
		t.Fatal("--yes must still vault without a terminal")
	}
}

// --dry-run is checked before the consent gate, so the read-only command stays
// read-only and exits 0 in a script.
func TestReviewAndVaultDryRunWritesNothing(t *testing.T) {
	dialled := countingDaemon(t)
	notATerminal(t)
	t.Cleanup(func(d bool) func() { return func() { discoverDryRun = d } }(discoverDryRun))
	discoverDryRun = true

	if err := reviewAndVault([]template.Finding{
		{Provider: "aws", Instance: "default", Fields: map[string]string{"access_key_id": "AKIA1"}, Source: "~/.aws/credentials"},
	}, false); err != nil {
		t.Fatalf("--dry-run is not a failure: %v", err)
	}
	if n := atomic.LoadInt32(dialled); n != 0 {
		t.Fatalf("--dry-run contacted the daemon %d time(s)", n)
	}
}
