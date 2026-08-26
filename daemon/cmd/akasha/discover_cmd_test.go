package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// vaultFindings printed a ✗ per failed credential and then returned nil, so the
// command exited 0 whether it had vaulted everything or nothing. A ✗ on stderr
// is invisible to a provisioning script; the exit status is the only thing it
// reads, and it said success over an empty vault. The usual cause is a daemon
// that is not running, which is exactly the state a first-run script hits.
func TestVaultFindingsReportsFailures(t *testing.T) {
	// A socket path that cannot be dialled: every VaultFinding must fail.
	old := socketPath
	t.Cleanup(func() { socketPath = old })
	socketPath = filepath.Join(t.TempDir(), "not-a-socket")

	err := vaultFindings([]template.Finding{
		{Provider: "aws", Instance: "default", Fields: map[string]string{"access_key_id": "AKIA1"}, Source: "test"},
		{Provider: "aws", Instance: "prod", Fields: map[string]string{"access_key_id": "AKIA2"}, Source: "test"},
	})
	if err == nil {
		t.Fatal("vaulting nothing must not report success — a script reads only the exit status")
	}
	// The count is what tells a human whether this was total or partial.
	if !strings.Contains(err.Error(), "2 of 2") {
		t.Errorf("error should report how many of how many failed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "akasha start") {
		t.Errorf("error should name the usual cause, got: %v", err)
	}
}

// The success path must stay quiet: an empty finding list is not a failure, and
// returning an error here would make `discover` fail on a clean machine.
func TestVaultFindingsSucceedsWithNothingToDo(t *testing.T) {
	old := socketPath
	t.Cleanup(func() { socketPath = old })
	socketPath = filepath.Join(t.TempDir(), "not-a-socket")

	if err := vaultFindings(nil); err != nil {
		t.Fatalf("no findings is not a failure: %v", err)
	}
}
