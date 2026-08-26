package setup

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// requestLog records the endpoints setup asked the daemon for, which is how a
// test proves a write was never ATTEMPTED: setup reports its vaulting failures
// and carries on either way, so the printed output cannot tell "declined" apart
// from "tried and could not".
//
// It counts endpoints rather than connections because setup dials for two
// unrelated reasons — vaulting a finding, and the orphan sweep that has to run
// whether or not anything was vaulted — and a bare connection count reads the
// second as the first.
type requestLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *requestLog) add(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, path)
}

func (l *requestLog) count(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, p := range l.seen {
		if p == path {
			n++
		}
	}
	return n
}

// writes counts every request that is not the orphan sweep.
func (l *requestLog) writes() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, p := range l.seen {
		if p != "/vault/purge" {
			n++
		}
	}
	return n
}

// countingDaemon listens on a unix socket and logs what is asked of it. It
// answers nothing: every call fails, which setup reports and survives.
func countingDaemon(t *testing.T) (sock string, log *requestLog) {
	t.Helper()
	// Short path: a unix socket under the temp dir t.TempDir() hands out on
	// macOS exceeds the 104-byte sun_path limit.
	dir, err := os.MkdirTemp("/tmp", "akset")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	rec := &requestLog{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// The deadline is only so a client that connects and says nothing
			// cannot wedge the accept loop; the request line is already on the
			// wire by the time we get here.
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, _ := bufio.NewReader(c).ReadString('\n')
			if f := strings.Fields(line); len(f) >= 2 {
				rec.add(f[1])
			} else {
				rec.add("(unreadable)") // unattributable, so count it as a write
			}
			c.Close()
		}
	}()
	return ln.Addr().String(), rec
}

// pipeStdin stands in for stdin that is not a terminal — CI, a Makefile, the
// `curl | sh` a first-run install actually arrives through — whatever the test
// binary itself was started from.
func pipeStdin(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r
}

func fixtureFindings() []template.Finding {
	return []template.Finding{
		{Provider: "aws", Instance: "default", Fields: map[string]string{"access_key_id": "AKIAFAKE"}, Source: "~/.aws/credentials"},
	}
}

// `akasha setup` vaulted every finding with no listing and no prompt at all:
// `discover`'s review UI did not exist on this path, and this is the FIRST
// command a new user runs — usually from a `curl | sh` whose stdin is the
// installer script, not a person. An unattended run must now decline.
func TestSetupDoesNotVaultUnattended(t *testing.T) {
	old := AssumeYes
	t.Cleanup(func() { AssumeYes = old })
	AssumeYes = false

	sock, log := countingDaemon(t)
	vaultDiscovered(sock, filepath.Join(t.TempDir(), "vault.db"), fixtureFindings(), pipeStdin(t))

	if n := log.writes(); n != 0 {
		t.Fatalf("the daemon was asked for %d write(s) — credentials were vaulted with nobody asked", n)
	}
}

// Declining to vault says nothing about the chains a PREVIOUS run orphaned, and
// the sweep that collects them used to run only after a successful vaulting
// pass. Now that an unattended setup declines by default, that left the machines
// least likely to see a person the ones whose vault only ever grows.
func TestSetupSweepsOrphansEvenWhenNothingIsVaulted(t *testing.T) {
	old := AssumeYes
	t.Cleanup(func() { AssumeYes = old })
	AssumeYes = false

	for _, tc := range []struct {
		name     string
		findings []template.Finding
	}{
		{"declined", fixtureFindings()},
		{"nothing found", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, log := countingDaemon(t)
			vaultDiscovered(sock, filepath.Join(t.TempDir(), "vault.db"), tc.findings, pipeStdin(t))

			if n := log.count("/vault/purge"); n != 1 {
				t.Fatalf("the orphan sweep ran %d time(s), want 1: %+v", n, log.seen)
			}
			if n := log.writes(); n != 0 {
				t.Fatalf("nothing was vaulted, but %d write(s) were sent: %+v", n, log.seen)
			}
		})
	}
}

// --yes is how an unattended install says yes. It is a deliberate flag, which
// is the entire point — and devcontainers and provisioning scripts depend on
// it, so the fix above must not have taken the escape hatch with it.
func TestSetupYesStillVaults(t *testing.T) {
	old := AssumeYes
	t.Cleanup(func() { AssumeYes = old })
	AssumeYes = true

	sock, log := countingDaemon(t)
	vaultDiscovered(sock, filepath.Join(t.TempDir(), "vault.db"), fixtureFindings(), pipeStdin(t))

	if n := log.writes(); n == 0 {
		t.Fatal("--yes must still vault without a terminal")
	}
}
