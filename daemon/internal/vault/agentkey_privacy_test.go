package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

// The agent key used to BE its own key_id, so `akasha agent list` printed every
// live bearer credential and key_hash hashed the value in the adjacent column.
// These pin the split: key_id names a key, key_hash authenticates it, and the
// plaintext exists only in CreateAgentKey's return value.

func openTestVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Open(filepath.Join(t.TempDir(), "vault.db"), Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestAgentKeyIDIsNotTheSecret(t *testing.T) {
	v := openTestVault(t)

	keyID, plaintext, err := v.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	if keyID == plaintext {
		t.Fatal("key_id must not be the bearer key")
	}
	if !strings.HasPrefix(keyID, "ak_") {
		t.Errorf("key_id = %q, want an ak_ handle", keyID)
	}
	if !strings.HasPrefix(plaintext, "agt_") {
		t.Errorf("plaintext = %q, want an agt_ key", plaintext)
	}

	// The key must not be recoverable from the row, by any column.
	var storedKeyID, storedHash string
	if err := v.db.QueryRow(
		`SELECT key_id, key_hash FROM agent_keys WHERE agent_id = ?`, "claude",
	).Scan(&storedKeyID, &storedHash); err != nil {
		t.Fatal(err)
	}
	for name, col := range map[string]string{"key_id": storedKeyID, "key_hash": storedHash} {
		if strings.Contains(col, plaintext) {
			t.Errorf("column %s contains the plaintext key", name)
		}
	}

	// Nor from the listing API that `agent list` renders.
	keys, err := v.ListAgentKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if strings.Contains(k.KeyID, plaintext) {
			t.Fatal("ListAgentKeys leaked the bearer key")
		}
	}

	// And it still works.
	if got, err := v.VerifyAgentKey(plaintext); err != nil || got != "claude" {
		t.Fatalf("VerifyAgentKey(plaintext) = %q, %v; want claude, nil", got, err)
	}
}

// Revoking takes the public handle, so the bearer secret never has to be pasted
// onto a command line (where it lands in shell history).
func TestRevokeByPublicKeyID(t *testing.T) {
	v := openTestVault(t)
	keyID, plaintext, err := v.CreateAgentKey("cursor")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RevokeAgentKey(keyID); err != nil {
		t.Fatalf("revoke by handle: %v", err)
	}
	if _, err := v.VerifyAgentKey(plaintext); err != ErrAgentKeyRevoked {
		t.Fatalf("after revoke: err = %v, want ErrAgentKeyRevoked", err)
	}
}

// RegisterAgentKey re-admits a key read out of an IDE config — an arbitrary
// caller-supplied string. It must not land that string in key_id either.
func TestRegisterAgentKeyDoesNotStorePlaintext(t *testing.T) {
	v := openTestVault(t)
	const foreign = "agt_orphaned_key"

	if err := v.RegisterAgentKey("claude", foreign); err != nil {
		t.Fatal(err)
	}
	var keyID string
	if err := v.db.QueryRow(
		`SELECT key_id FROM agent_keys WHERE agent_id = ?`, "claude",
	).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID == foreign {
		t.Fatal("RegisterAgentKey stored the plaintext as key_id")
	}
	if got, err := v.VerifyAgentKey(foreign); err != nil || got != "claude" {
		t.Fatalf("re-admitted key must verify: %q, %v", got, err)
	}
	// Re-admitting is idempotent and must not collide on the PRIMARY KEY.
	if err := v.RegisterAgentKey("claude", foreign); err != nil {
		t.Fatalf("second re-admit: %v", err)
	}
}

// TestMigrationRewritesLegacyPlaintextKeyIDs: existing installs have rows whose
// key_id IS the key. Reopening the vault must rewrite them, or the fix helps
// nobody who already ran akasha.
func TestMigrationRewritesLegacyPlaintextKeyIDs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(dbPath, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}

	// Recreate the legacy shape: key_id == plaintext.
	const legacy = "agt_claude_LEGACYPLAINTEXTKEY"
	if _, err := v.db.Exec(
		`INSERT INTO agent_keys (key_id, agent_id, key_hash, created_at)
		 VALUES (?, ?, ?, datetime('now'))`,
		legacy, "claude", hashKey(legacy),
	); err != nil {
		t.Fatal(err)
	}
	v.Close()

	v2, err := Open(dbPath, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()

	var keyID string
	if err := v2.db.QueryRow(
		`SELECT key_id FROM agent_keys WHERE agent_id = ?`, "claude",
	).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID == legacy {
		t.Fatal("migration did not rewrite the legacy plaintext key_id")
	}
	if !strings.HasPrefix(keyID, "ak_") {
		t.Errorf("migrated key_id = %q, want an ak_ handle", keyID)
	}

	// Critically, the existing key must keep working — a migration that
	// silently invalidated live agent keys would be worse than the leak.
	if got, err := v2.VerifyAgentKey(legacy); err != nil || got != "claude" {
		t.Fatalf("legacy key stopped working after migration: %q, %v", got, err)
	}
	// And revoke now takes the new handle.
	if err := v2.RevokeAgentKey(keyID); err != nil {
		t.Fatalf("revoke by migrated handle: %v", err)
	}
}

// The migration must be idempotent — Open runs it on every daemon start.
func TestMigrationIsIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(dbPath, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	keyID, plaintext, err := v.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	for i := 0; i < 3; i++ {
		vn, err := Open(dbPath, Options{AllowNewVaultKey: true})
		if err != nil {
			t.Fatal(err)
		}
		var got string
		if err := vn.db.QueryRow(
			`SELECT key_id FROM agent_keys WHERE agent_id = ?`, "claude").Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != keyID {
			t.Fatalf("reopen %d: key_id drifted %q -> %q", i, keyID, got)
		}
		if _, err := vn.VerifyAgentKey(plaintext); err != nil {
			t.Fatalf("reopen %d: key stopped verifying: %v", i, err)
		}
		vn.Close()
	}
}
