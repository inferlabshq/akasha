package vault_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/internal/vault"
)

func TestBackupRestoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	backupPath := filepath.Join(dir, "backup.akb")
	passphrase := []byte("correct horse battery staple")

	// Open vault (generates ML-KEM keypair), store a secret.
	v, err := vault.Open(dbPath, vault.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	token, err := v.Store("super-secret-value", "APIKey", "critical", "agent", "tool", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// Back up the key.
	if err := v.BackupKey(backupPath, passphrase); err != nil {
		t.Fatalf("backup: %v", err)
	}
	v.Close()

	// Verify the backup file exists and is non-trivial.
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	if info.Size() < 17 {
		t.Fatalf("backup too small: %d bytes", info.Size())
	}

	// Restore should succeed with the right passphrase and leave the
	// secret retrievable.
	if err := vault.RestoreKey(dbPath, backupPath, passphrase); err != nil {
		t.Fatalf("restore: %v", err)
	}

	v2, err := vault.Open(dbPath, vault.Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer v2.Close()

	got, err := v2.Retrieve(token, "tool")
	if err != nil {
		t.Fatalf("retrieve after restore: %v", err)
	}
	if got != "super-secret-value" {
		t.Fatalf("got %q after restore", got)
	}
}

func TestRestoreWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	backupPath := filepath.Join(dir, "backup.akb")

	v, _ := vault.Open(dbPath, vault.Options{})
	v.Store("x", "APIKey", "high", "a", "t", 0)
	if err := v.BackupKey(backupPath, []byte("right-pass")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	err := vault.RestoreKey(dbPath, backupPath, []byte("wrong-pass"))
	if err == nil {
		t.Fatal("expected error restoring with wrong passphrase")
	}
}

func TestPurgeExpired(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// One entry with a 1ns TTL (expires immediately), one that never expires.
	v.Store("expired", "APIKey", "high", "a", "t", time.Nanosecond)
	v.Store("permanent", "APIKey", "high", "a", "t", 0)
	time.Sleep(5 * time.Millisecond)

	n, err := v.PurgeExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged, got %d", n)
	}

	total, _, _ := v.Stats()
	if total != 1 {
		t.Fatalf("expected 1 remaining, got %d", total)
	}
}
