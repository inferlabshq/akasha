package setup

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// "Is the daemon running?" is a per-user question, and it used to be asked of a
// machine-wide port.
//
// Measured on a Mac with two accounts, running `akasha setup` as the second
// user, with the first user's daemon up:
//
//	  ✓ Daemon already running                              <- the OTHER user's
//	Error: vault: migrate: unable to open database file (14)
//
// Loopback is shared by every account, so the second user found the first
// user's daemon on 127.0.0.1:7743, skipped registering a service of their own,
// and then failed opening a data directory nothing had created. akasha could
// not be set up for a second user on the machine at all.
//
// The unix socket is the right question because it is the right boundary: it
// sits in this user's data directory at mode 0600, so reaching it already means
// being this user.
func TestDaemonLivenessIsScopedToThisUsersSocket(t *testing.T) {
	// Short path on purpose: a unix socket under the temp dir t.TempDir() hands
	// out on macOS exceeds the 104-byte sun_path limit, and this test skipping
	// itself proves nothing.
	dir, err := os.MkdirTemp("/tmp", "akscope")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "akasha.sock")

	if isDaemonRunning(sock) {
		t.Fatal("reported a daemon with nothing listening on this user's socket")
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("bind unix socket: %v", err)
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

	if !isDaemonRunning(sock) {
		t.Error("did not see a daemon that is listening on this user's socket")
	}

	// A socket path that exists as a FILE but has nothing behind it is the
	// stale-socket case, and it must read as "not running" rather than as a
	// daemon that will never answer.
	stale := filepath.Join(dir, "stale.sock")
	if err := os.WriteFile(stale, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if isDaemonRunning(stale) {
		t.Error("a stale socket file was reported as a running daemon")
	}

	// And an empty path is not an invitation to go looking elsewhere.
	if isDaemonRunning("") {
		t.Error("no socket path should mean no daemon, not a fallback probe")
	}
}
