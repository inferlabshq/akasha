package main

import (
	"errors"
	"strings"
	"testing"
)

// The daemon's error bodies are its most useful output — they carry the repair
// step. Before this, the socket transport dropped the status line and returned
// the prose as if it were data, so `akasha list` surfaced a revoked agent key
// as "unexpected response: ..." instead of the instruction the daemon sent.
func TestSplitRawResponseSurfacesDaemonErrors(t *testing.T) {
	const revoked = "agent key has been revoked — if this was not intended, issue a new one with `akasha agent resync --rotate`"
	raw := "HTTP/1.0 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\n" + revoked + "\n"

	code, body := splitRawResponse(raw)
	if code != 401 {
		t.Fatalf("status code = %d, want 401", code)
	}
	err := statusError(code, body)
	if err == nil {
		t.Fatal("a 401 must be reported as an error, not returned as data")
	}
	if err.Error() != revoked {
		t.Errorf("error lost the daemon's remediation text:\n got: %s\nwant: %s", err, revoked)
	}
}

func TestSplitRawResponsePassesSuccessThrough(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}"
	code, body := splitRawResponse(raw)
	if code != 200 {
		t.Fatalf("status code = %d, want 200", code)
	}
	if body != `{"status":"ok"}` {
		t.Errorf("body = %q", body)
	}
	if err := statusError(code, body); err != nil {
		t.Errorf("200 must not be an error: %v", err)
	}
}

// An unparseable status line must not turn a working response into a failure:
// the body is still handed on, and a genuinely broken one fails at decode.
func TestStatusErrorToleratesUnparseableStatusLine(t *testing.T) {
	code, body := splitRawResponse("garbage-without-a-status-line")
	if code != 0 {
		t.Fatalf("expected an unparseable status line to yield 0, got %d", code)
	}
	if err := statusError(code, body); err != nil {
		t.Errorf("unknown status must not be treated as an error: %v", err)
	}
}

func TestStatusErrorFallsBackWhenBodyEmpty(t *testing.T) {
	err := statusError(500, "   ")
	if err == nil {
		t.Fatal("a 500 with an empty body must still be an error")
	}
	if err.Error() != "daemon returned HTTP 500" {
		t.Errorf("unhelpful fallback message: %v", err)
	}
}

// The HTTP fallback dials a FIXED shared port, so when a named socket is
// unreachable it can reach a different daemon serving a different vault. That
// silently redirected a write into the wrong vault once already, so a named
// target that is down must be an error, not a reroute.
func TestNamedTargetDisablesTheHTTPFallback(t *testing.T) {
	f := rootCmd.PersistentFlags()

	if targetedExplicitly() {
		t.Fatal("no flags set: the fallback should remain available for --http-only daemons")
	}

	if err := f.Set("socket", "/tmp/some-specific.sock"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.Set("socket", "")
		f.Lookup("socket").Changed = false
		f.Lookup("db").Changed = false
	})
	if !targetedExplicitly() {
		t.Error("--socket names a target, so the fallback must be disabled")
	}

	f.Lookup("socket").Changed = false
	if err := f.Set("db", "/tmp/other.db"); err != nil {
		t.Fatal(err)
	}
	if !targetedExplicitly() {
		t.Error("--db names a vault, so the fallback must be disabled too")
	}
}

// The refusal has to explain itself: which socket, and why reaching the shared
// port instead would be wrong.
func TestNoFallbackErrExplainsTheRisk(t *testing.T) {
	err := noFallbackErr("/tmp/scratch.sock", errors.New("connect: no such file or directory"))
	for _, want := range []string{
		"/tmp/scratch.sock",
		"7743",
		"DIFFERENT daemon",
		"different vault",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}
