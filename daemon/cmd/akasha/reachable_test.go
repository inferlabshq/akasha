package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// `akasha start` refuses when a daemon is already serving the socket, and the
// property that makes that refusal safe is that liveness is decided by DIALLING
// rather than by the socket file existing.
//
// The two states look identical on disk and mean opposite things:
//
//	a stale socket left by a crash   -> nothing behind it; a start MUST proceed
//	a live daemon on that path       -> a start must refuse, or it rebinds
//
// Getting it backwards either way is its own outage. Checking existence would
// wedge every start after a crash; checking nothing is what let a second start
// rebind over the first — measured as uid 1001, inode 698075 becoming 698088
// with both processes alive and no warning, and the survivor left unreachable
// once either exited and unlinked the path.
func TestDaemonReachableDistinguishesLiveFromStale(t *testing.T) {
	// Short path: a unix socket under the temp dir t.TempDir() hands out on
	// macOS exceeds the 104-byte sun_path limit, and a skipped test proves
	// nothing.
	dir, err := os.MkdirTemp("/tmp", "akreach")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	absent := filepath.Join(dir, "absent.sock")
	if DaemonReachable(absent) {
		t.Error("no socket at all reported as a running daemon")
	}

	// A file at the path with nothing behind it: what a crash leaves.
	stale := filepath.Join(dir, "stale.sock")
	if err := os.WriteFile(stale, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if DaemonReachable(stale) {
		t.Error("a stale socket file reported as a running daemon — every start after a crash would refuse")
	}

	// A real listener.
	live := filepath.Join(dir, "live.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if !DaemonReachable(live) {
		t.Error("a live daemon was not seen — a second start would rebind over it")
	}

	// And once it goes away, the path is free again even though the file may
	// still be there.
	ln.Close()
	if DaemonReachable(live) {
		t.Error("a closed listener still reported as reachable")
	}
}
