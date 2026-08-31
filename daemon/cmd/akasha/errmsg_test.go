package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The client tries two transports. When both fail it must say what each one
// said — it used to report the SOCKET's error after the HTTP attempt failed,
// describing a failure from two steps ago and discarding the one that had just
// happened.
func TestBothPathsFailedNamesBothTransports(t *testing.T) {
	err := bothPathsFailedErr("/home/dev/.akasha/akasha.sock",
		errors.New("connect: no such file or directory"),
		errors.New("connect: connection refused"))
	msg := err.Error()

	for _, want := range []string{
		"/home/dev/.akasha/akasha.sock", // which socket
		"no such file or directory",     // what the socket said
		"127.0.0.1",                     // the fallback
		"connection refused",            // what the fallback said
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
}

// It must not assert a single cause. "is `akasha start` running?" is the wrong
// question whenever the daemon IS running and something else stopped the client
// reaching it — a --socket naming a different vault, a stale socket file, a path
// over the length limit. Being sent to restart a daemon that is already up is
// the failure this message exists to stop.
func TestBothPathsFailedDoesNotDiagnoseOneCause(t *testing.T) {
	msg := bothPathsFailedErr("/s/akasha.sock", errors.New("a"), errors.New("b")).Error()

	if strings.Contains(msg, "(is `akasha start` running?)") {
		t.Error("the message still asserts one cause as though it were a diagnosis")
	}
	// It should still OFFER that cause, conditionally, alongside the others.
	for _, want := range []string{"akasha start", "--socket", "stale socket"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error stopped offering %q as a thing to check:\n%s", want, msg)
		}
	}
}

// A restored key alone leaves the broker dead, and that failure does not
// announce itself: the daemon starts, status is green, and every brokered call
// fails later with `no template for provider "..."`.
func TestRestoreNamesTheTemplatesWhenTheyAreMissing(t *testing.T) {
	out := restoreNextSteps("/home/dev/.akasha/vault.db", filepath.Join(t.TempDir(), "absent"))

	if !strings.Contains(out, "/home/dev/.akasha/vault.db") {
		t.Error("the vault database is not named")
	}
	for _, want := range []string{"MISSING", "no template for provider", "installer"} {
		if !strings.Contains(out, want) {
			t.Errorf("the missing-templates case does not mention %q:\n%s", want, out)
		}
	}
}

// …and when they ARE there it must say so rather than sending someone to find a
// directory they already have. A recovery procedure that tells you to fix
// something already correct is one you stop trusting.
func TestRestoreConfirmsTemplatesThatArePresent(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"github.yaml", "aws.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A subdirectory is not a template and must not be counted.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	out := restoreNextSteps("/db", dir)
	if strings.Contains(out, "MISSING") {
		t.Errorf("templates are present but reported missing:\n%s", out)
	}
	if !strings.Contains(out, "already here (2 in") {
		t.Errorf("want a count of 2 real templates, got:\n%s", out)
	}
}
