package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// copyVaultDBOnly copies vault.db and nothing else — no -wal, no -shm. That is
// what a human copying a file, a backup tool, or `uninstall --export` actually
// takes away, and it is the only copy shape worth asserting on.
func copyVaultDBOnly(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// GUARANTEE: after a clean Close, vault.db ALONE is the whole vault.
//
// In WAL mode every write stays in vault.db-wal until something checkpoints,
// and SQLite only does that by itself when the LAST connection to the file
// closes — which is never true while a CLI process (or, in production, the
// daemon) also has the vault open. So Close has to checkpoint explicitly, or a
// backup taken around a shutdown is a 4 KB header with no rows in it.
func TestCloseCheckpointsWhileAnotherHandleIsOpen(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "vault.db")

	daemon, err := vault.Open(db, vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	token, err := daemon.Store("fixture-secret-value", "APIKey", "high", "agent", "wrap", 0)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// A second process holding the same vault open — `akasha vault backup`,
	// `akasha status`, anything. Its presence is what stops SQLite from
	// checkpointing on its own when the daemon's handle goes away.
	other, err := vault.Open(db, vault.Options{})
	if err != nil {
		t.Fatalf("second handle: %v", err)
	}
	defer other.Close()

	if err := daemon.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	copyPath := filepath.Join(dir, "copy.db")
	copyVaultDBOnly(t, db, copyPath)

	restored, err := vault.Open(copyPath, vault.Options{})
	if err != nil {
		t.Fatalf("a copy of vault.db taken after a clean shutdown must open: %v", err)
	}
	defer restored.Close()

	got, err := restored.Retrieve(token, "wrap")
	if err != nil {
		t.Fatalf("the copied vault.db holds no entries — the write-ahead log was never "+
			"folded in, so every backup of this vault is empty: %v", err)
	}
	if got != "fixture-secret-value" {
		t.Fatalf("copied vault returned %q", got)
	}
}

// Checkpoint is the guarantee the copy paths ask for directly, and unlike Close
// it must report failure rather than absorb it.
func TestCheckpointMakesDBCopyRestorable(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "vault.db")

	v, err := vault.Open(db, vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer v.Close()

	token, err := v.Store("fixture-secret-value", "APIKey", "high", "agent", "wrap", 0)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := v.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}

	// The vault is still open and still being written to; that is exactly the
	// state a backup runs in, so the copy has to be good anyway.
	copyPath := filepath.Join(dir, "copy.db")
	copyVaultDBOnly(t, db, copyPath)

	restored, err := vault.Open(copyPath, vault.Options{})
	if err != nil {
		t.Fatalf("vault.Open(copy): %v", err)
	}
	defer restored.Close()

	if got, err := restored.Retrieve(token, "wrap"); err != nil || got != "fixture-secret-value" {
		t.Fatalf("copy taken after Checkpoint: got %q err %v", got, err)
	}
}

// A checkpoint on a closed vault has to surface an error, not report success —
// a caller about to copy the file is relying on this return value.
func TestCheckpointOnClosedVaultErrors(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	v.Close()
	if err := v.Checkpoint(); err == nil {
		t.Fatal("Checkpoint on a closed vault should error")
	}
}
