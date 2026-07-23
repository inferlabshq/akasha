package vault

// White-box tests for branches only reachable with access to internals:
// legacy-cipher migration, the locked-vault guard, the crypto-failure panic,
// and keychain-absent error paths.

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// An entry tagged with an unknown cipher version must fail to decrypt.
func TestDecryptUnknownCipher(t *testing.T) {
	dir := t.TempDir()
	v, err := Open(filepath.Join(dir, "v.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	token := tokenPrefix + "weird"
	v.db.Exec(`INSERT INTO vault (token, encrypted_value, category, risk, agent_id, tool_name, created_at, cipher_version)
		VALUES (?, ?, 'c', 'r', 'a', 't', ?, 99)`, token, []byte("xx"), time.Now().UTC())
	if _, err := v.Retrieve(token, "t"); err == nil {
		t.Fatal("expected error for unknown cipher version")
	}
}

// Legacy AES entry but no legacy key available → decrypt errors.
func TestDecryptLegacyWithoutKey(t *testing.T) {
	dir := t.TempDir()
	v, err := Open(filepath.Join(dir, "v.db"), Options{}) // no legacy key set
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	token := tokenPrefix + "leg2"
	v.db.Exec(`INSERT INTO vault (token, encrypted_value, category, risk, agent_id, tool_name, created_at, cipher_version)
		VALUES (?, ?, 'c', 'r', 'a', 't', ?, 1)`, token, []byte("xx"), time.Now().UTC())
	if _, err := v.Retrieve(token, "t"); err == nil {
		t.Fatal("expected error: legacy entry with no legacy key")
	}
}

// resolveKeys must fail loudly (not regenerate) when the DB has key material
// but the keychain key is gone — the data-loss guard.
func TestResolveKeysLockedVault(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")

	v, err := Open(db, Options{}) // creates keychain key + DB kem_ciphertext
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	keyring.Delete(keyringService, keyringMLKEMSK) // remove key; ciphertext stays

	_, err = Open(db, Options{})
	if err == nil {
		t.Fatal("expected locked-vault error when keychain key is missing")
	}
}

// resolveKeys must ALSO fail loudly (not regenerate) in the inverse half-state:
// the keychain key AND kem_ciphertext are gone but encrypted rows survive — the
// exact corruption a botched uninstall purge can leave. Regenerating a key here
// would silently orphan every surviving entry, so Open must refuse.
func TestResolveKeysOrphanedRows(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")

	v, err := Open(db, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Store("sk-live", "APIKey", "critical", "agent", "wrap", 0); err != nil {
		t.Fatal(err)
	}
	// Simulate the half-purge while the handle is open: drop the KEM ciphertext
	// metadata but leave the encrypted vault rows in place...
	if _, err := v.db.Exec(`DELETE FROM metadata WHERE key = 'kem_ciphertext'`); err != nil {
		t.Fatal(err)
	}
	v.Close()
	// ...and drop the keychain key. Now both halves of the key material are gone
	// but an encrypted row survives.
	keyring.Delete(keyringService, keyringMLKEMSK)

	_, err = Open(db, Options{})
	if err == nil {
		t.Fatal("expected corrupt-vault error when ciphertext is gone but rows survive")
	}
	if !strings.Contains(err.Error(), "orphan") && !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("error should explain the orphan risk, got: %v", err)
	}
}

// BackupKey needs the keychain key present.
func TestBackupKeyMissingKey(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")
	v, err := Open(db, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	keyring.Delete(keyringService, keyringMLKEMSK)
	if err := v.BackupKey(filepath.Join(dir, "b.akb"), []byte("pw")); err == nil {
		t.Fatal("expected error backing up with no keychain key")
	}
}

// randomID must panic if the system CSPRNG fails (it underpins token secrecy).
func TestRandomIDPanicsOnRandFailure(t *testing.T) {
	old := cryptoRandRead
	cryptoRandRead = func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() {
		cryptoRandRead = old
		if recover() == nil {
			t.Fatal("randomID should panic when crypto/rand fails")
		}
	}()
	_ = randomID(8)
}
