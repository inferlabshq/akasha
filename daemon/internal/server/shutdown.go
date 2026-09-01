package server

import (
	"fmt"
	"net/http"
	"sync"
)

// STOPPING THE DAEMON was not something akasha could do.
//
// There was no pidfile, no `akasha stop`, and no endpoint — the only clean stop
// was a signal somebody else had to send. `uninstall` therefore ran
// `systemctl --user disable --now akasha`, DISCARDED its exit status, and then
// unlinked the socket. On any machine without a working systemd user manager —
// which `setup` itself steers people towards, telling them to "start the daemon
// yourself with `akasha start`" — the result was:
//
//	uninstall --purge  →  "Akasha fully removed."
//	                      ~/.akasha gone, keychain key gone, audit log gone
//	                      the process still alive, still bound to 127.0.0.1:7743,
//	                      still answering a pre-issued agent key with plaintext
//
// Removing the socket did not stop it. It removed the evidence: the one file a
// person would have looked at to notice the daemon was still there. And because
// the MCP surface is TCP, the ghost kept the port across a reinstall, so a
// later vault_assume was answered by the vault the user had just purged, with
// the audit log already deleted and `agent revoke` no longer able to open the
// database to revoke the key that was still working.
//
// A stop the product cannot perform is a stop the product must not claim. This
// is the mechanism; uninstall.go is where the claim gets checked against it.

// stopper holds the daemon's clean-stop trigger. It is a func rather than a
// channel so the wiring stays in main, where the signal path already lives:
// /shutdown enters the SAME path a SIGTERM does, and therefore gets the same
// drain and the same write-ahead-log checkpoint. A second stop path with its
// own idea of a clean exit is how the empty-vault.db bug came back.
type stopper struct {
	mu sync.Mutex
	fn func()
}

func (s *stopper) set(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fn = fn
}

func (s *stopper) get() func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fn
}

// SetStopper wires the clean-stop trigger. Called once from main, alongside the
// signal handler it shares.
func (s *Server) SetStopper(fn func()) { s.stop.set(fn) }

// handleShutdown stops the daemon.
//
// Human-only, exactly like /vault/purge and for the same reason: an agent has
// no legitimate need to turn the credential broker off, and "deny service to
// the thing that audits me" is a capability worth withholding even when the
// same-uid ceiling means a determined local process has other options.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !isHuman(r) {
		http.Error(w, "stopping the daemon is done by the person at the keyboard, not by an agent; "+
			"run `akasha stop` in a terminal", http.StatusForbidden)
		return
	}
	fn := s.stop.get()
	if fn == nil {
		// An embedded server with no lifecycle to stop. Say so rather than
		// reporting a shutdown that will not happen — the whole point here.
		http.Error(w, "this daemon has no stop path wired; send it SIGTERM", http.StatusNotImplemented)
		return
	}

	// Answer BEFORE stopping, or the caller sees a dropped connection and
	// cannot tell a successful shutdown from a daemon that died mid-request.
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"stopping"}`)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go fn()
}
