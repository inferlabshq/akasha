package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// recordingDaemon captures the request line of every call, so a test can assert
// which endpoints a command actually reached.
func recordingDaemon(t *testing.T) func() []string {
	t.Helper()
	// Short path: a unix socket under the temp dir t.TempDir() hands out on
	// macOS exceeds the 104-byte sun_path limit, and a test that skips itself
	// proves nothing.
	dir, err := os.MkdirTemp("/tmp", "akpurge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			mu.Lock()
			seen = append(seen, strings.TrimSpace(line))
			mu.Unlock()
			// "Connection: close" is load-bearing, not tidiness.
			//
			// The client here is net/http with keep-alives on (see
			// provision.NewSocket), so an HTTP/1.1 response carrying only a
			// Content-Length tells it the connection may be REUSED. This
			// handler serves one request per connection and closes, and the
			// transport has no way to know that: it returns the socket to its
			// pool, picks it for the next call, writes onto a closed
			// connection, and fails. A POST with a body is not replayable, so
			// net/http does not retry it -- and PurgeOrphans() drops the error
			// -- meaning the request vanishes with nothing reported anywhere.
			//
			// Whether the transport notices the EOF before the next request is
			// a pure race, so the test passed locally and on unloaded runners
			// and failed on a loaded CI runner under -race, roughly one run in
			// a few hundred, with a "requests made" list one entry short.
			// Announcing the close makes the client open a fresh connection.
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"))
			c.Close()
		}
	}()
	old := socketPath
	socketPath = ln.Addr().String()
	t.Cleanup(func() { socketPath = old; ln.Close() })
	// A snapshot under the mutex, rather than a pointer into a slice the accept
	// goroutine is still appending to.
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// Discovery orphans a credential chain every time it runs, and must sweep them.
//
// It mints a fresh credential-map token on each run and re-points the label at
// it, leaving the previous copy reachable by no label, profile or grant —
// invisible to `list` and removable by no command. Measured before this fix:
// three runs over one unchanged profile took vault_total from 3 to 6 to 9 while
// `list` showed the same single label throughout. A credential that has been
// ROTATED therefore leaves its old value in the vault indefinitely, and
// discovery is the documented way to pick up the new one.
//
// PurgeOrphans is built for this and says so in its own doc comment. `setup`
// has always called it; this path never did.
//
// The assertion is that the call is MADE. What it then collects is bounded by
// the sweep's own ten-minute grace window — an entry younger than that is
// indistinguishable from a store whose bind has not arrived yet — so a test
// that vaults and re-vaults within milliseconds can never observe the effect,
// and would pass just as happily with the call removed again.
func TestDiscoverSweepsTheChainsItOrphans(t *testing.T) {
	requests := recordingDaemon(t)
	t.Cleanup(func(d bool) func() { return func() { discoverDryRun = d } }(discoverDryRun))
	discoverDryRun = false

	_ = vaultFindings([]template.Finding{{
		Provider: "aws", Instance: "default",
		Fields: map[string]string{"access_key_id": "AKIA1"},
		Source: "a source path",
	}})

	var purged bool
	for _, line := range requests() {
		if strings.Contains(line, "/vault/purge") {
			purged = true
		}
	}
	if !purged {
		t.Errorf("discover never asked the daemon to sweep the chain it orphaned.\nrequests made: %v", requests())
	}
}
