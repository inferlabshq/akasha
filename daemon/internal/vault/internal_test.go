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
	v, err := Open(filepath.Join(dir, "v.db"), Options{AllowNewVaultKey: true})
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
	v, err := Open(filepath.Join(dir, "v.db"), Options{AllowNewVaultKey: true}) // no legacy key set
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

	v, err := Open(db, Options{AllowNewVaultKey: true}) // creates keychain key + DB kem_ciphertext
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	keyring.Delete(keyringService, keyringMLKEMSK) // remove key; ciphertext stays

	_, err = Open(db, Options{AllowNewVaultKey: true})
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

	v, err := Open(db, Options{AllowNewVaultKey: true})
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

	_, err = Open(db, Options{AllowNewVaultKey: true})
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
	v, err := Open(db, Options{AllowNewVaultKey: true})
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

// clearMachineKey removes the (test-isolated) keychain entry, so a guard test
// starts from a machine that has no vault yet. Without this the tests would
// depend on execution order: the first vault any test in this binary creates
// claims the shared entry, which is exactly the condition under test.
func clearMachineKey(t *testing.T) {
	t.Helper()
	keyring.Delete(keyringService, keyringMLKEMSK)
}

// Reproduces the accident this guard exists to stop: pointing --db at a path
// that does not exist made a production binary mint a new key straight over the
// one the REAL vault depends on. Nothing failed at the time — a running daemon
// holds its key in memory — so the damage only surfaced at the next restart, by
// which point every credential was undecryptable.
func TestOpenRefusesToRekeyTheMachineForANewVault(t *testing.T) {
	clearMachineKey(t)
	dir := t.TempDir()

	// The machine's real vault: created normally, owns the keychain key.
	real, err := Open(filepath.Join(dir, "real.db"), Options{})
	if err != nil {
		t.Fatalf("first vault should open: %v", err)
	}
	tok, err := real.Store("the-real-secret", "APIKey", "critical", "a", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	real.Close()

	// A second vault at a different path — the `--db /scratch/v.db` mistake.
	_, err = Open(filepath.Join(dir, "scratch.db"), Options{})
	if err == nil {
		t.Fatal("creating a second vault must not silently replace the machine's key")
	}
	for _, want := range []string{"refusing to create a new vault", "scratch.db", "AKASHA_ALLOW_NEW_VAULT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}

	// The real vault must still decrypt — proving the key was left alone.
	reopened, err := Open(filepath.Join(dir, "real.db"), Options{})
	if err != nil {
		t.Fatalf("the real vault must still open after the refusal: %v", err)
	}
	defer reopened.Close()
	if got, err := reopened.Retrieve(tok, "t"); err != nil || got != "the-real-secret" {
		t.Fatalf("real vault no longer decrypts: %q %v", got, err)
	}
}

// The escape hatch works, and does what it warns about: the new vault opens and
// the old one becomes undecryptable. Anyone who sets it has been told.
func TestOpenAllowsANewVaultKeyWhenExplicitlyPermitted(t *testing.T) {
	clearMachineKey(t)
	dir := t.TempDir()

	first, err := Open(filepath.Join(dir, "first.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := first.Store("old-secret", "APIKey", "critical", "a", "t", 0)
	first.Close()

	second, err := Open(filepath.Join(dir, "second.db"), Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("explicit opt-in should be allowed: %v", err)
	}
	second.Close()

	reopened, err := Open(filepath.Join(dir, "first.db"), Options{})
	if err == nil {
		if _, rerr := reopened.Retrieve(tok, "t"); rerr == nil {
			t.Error("expected the original vault to be undecryptable after an explicit rekey")
		}
		reopened.Close()
	}
}

// The env var reaches every entry point, since setup and the SDK take no flag.
func TestOpenEscapeHatchViaEnv(t *testing.T) {
	clearMachineKey(t)
	dir := t.TempDir()

	first, err := Open(filepath.Join(dir, "first.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	t.Setenv("AKASHA_ALLOW_NEW_VAULT", "1")
	second, err := Open(filepath.Join(dir, "second.db"), Options{})
	if err != nil {
		t.Fatalf("AKASHA_ALLOW_NEW_VAULT=1 should permit a new vault: %v", err)
	}
	second.Close()
}

// A genuine first run on a clean machine is unaffected — the guard only fires
// when a key already exists.
func TestOpenFirstRunStillWorks(t *testing.T) {
	clearMachineKey(t)
	v, err := Open(filepath.Join(t.TempDir(), "fresh.db"), Options{})
	if err != nil {
		t.Fatalf("first run on a clean keychain must succeed: %v", err)
	}
	defer v.Close()
	if _, err := v.Store("x", "APIKey", "low", "a", "t", 0); err != nil {
		t.Fatal(err)
	}
}
