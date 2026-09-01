package setup

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A daemon that will not stop must not be reported as removed.
//
// The shipped behaviour: `uninstall --purge` ran one `systemctl --user disable
// --now akasha`, discarded its exit status, unlinked the socket, and printed
// "Akasha fully removed." On a machine with no working systemd user manager the
// process was still alive, still bound to the loopback port, and still
// answering a pre-issued agent key with plaintext — with the audit log deleted
// and the vault key gone, so `agent revoke` could no longer revoke the key that
// still worked.
//
// Removing the socket was the worst part: it did not stop anything, it just
// removed the file a person would have looked at to notice.
func TestUninstallRefusesToClaimSuccessOverALiveDaemon(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)

	// seedDevEnv names a socket path but does not create the file, and the
	// assertion below is about whether uninstall REMOVES it — so it has to
	// exist first, or the test passes for the wrong reason.
	if err := os.WriteFile(opts.SocketPath, nil, 0600); err != nil {
		t.Fatal(err)
	}

	// A daemon that refuses the stop and keeps answering.
	stopCalled := 0
	opts.StopDaemon = func() error {
		stopCalled++
		return errors.New("connection refused")
	}
	opts.DaemonAlive = func() bool { return true }

	var err error
	out := captureStdout(t, func() { err = Uninstall(opts) })

	if err == nil {
		t.Fatal("uninstall reported success while the daemon was still running")
	}
	if stopCalled == 0 {
		t.Error("uninstall never asked the daemon to stop")
	}
	if strings.Contains(out, "Akasha fully removed") {
		t.Error(`the output still claims "Akasha fully removed"`)
	}
	for _, want := range []string{"still running", "akasha stop"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output should mention %q so the reader can finish the job:\n%s", want, out)
		}
	}
	// The socket must survive: it is both the evidence and the way back in.
	if _, statErr := os.Stat(opts.SocketPath); os.IsNotExist(statErr) {
		t.Error("the socket was removed while the daemon was still alive — that hides the survivor")
	}
}

// The other half: a daemon that does stop is stopped, the socket goes, and the
// claim is allowed to stand.
func TestUninstallReportsSuccessWhenTheDaemonActuallyStops(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)

	if err := os.WriteFile(opts.SocketPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	alive := true
	opts.StopDaemon = func() error { alive = false; return nil }
	opts.DaemonAlive = func() bool { return alive }

	var err error
	out := captureStdout(t, func() { err = Uninstall(opts) })
	if err != nil {
		t.Fatalf("a daemon that stops cleanly must not fail the uninstall: %v", err)
	}
	if !strings.Contains(out, "Daemon deregistered") {
		t.Errorf("a complete uninstall should say so:\n%s", out)
	}
	if _, statErr := os.Stat(opts.SocketPath); !os.IsNotExist(statErr) {
		t.Error("the socket should be gone once the daemon is")
	}
}

// A nil StopDaemon is "no stop path available", never "nothing is running".
// The distinction matters because the nil case is what an older caller — or a
// test — leaves behind, and the safe reading is the pessimistic one.
func TestNoStopPathIsNotTreatedAsAStoppedDaemon(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	opts.StopDaemon = nil
	opts.DaemonAlive = func() bool { return true }

	var err error
	out := captureStdout(t, func() { err = Uninstall(opts) })
	if err == nil {
		t.Fatal("with no way to stop a live daemon, uninstall must not claim to have removed it")
	}
	if strings.Contains(out, "Akasha fully removed") {
		t.Error(`the output still claims "Akasha fully removed"`)
	}
}
