package vault

// These tests exist to keep a DISCLOSURE honest, not to protect a behaviour.
//
// docs/THREATMODEL.md and docs/design/same-user-identity.md both state that on a
// default (no-passphrase) install the vault decrypts entirely offline: the
// ML-KEM secret key comes out of the OS keychain, the KEM ciphertext out of a
// PLAINTEXT metadata row in vault.db, and the two together are the whole key.
// No socket, no policy evaluation, no TTL, no audit record.
//
// A claim like that ages badly in a doc nobody can run. So it is measured here:
// the first test performs the offline decryption using only the two artefacts an
// attacker running as the user already has, touching neither Vault.Retrieve nor
// the daemon. If someone later moves the ciphertext, wraps it, or changes the
// derivation, this test breaks and the docs get revisited instead of quietly
// becoming false.
//
// The second test is the other half of the same sentence: with a passphrase, the
// identical procedure fails. That is what makes the recommendation in those docs
// — and the line `akasha status` prints — worth anything.

import (
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"testing"

	vaultcrypto "github.com/inferlabshq/akasha/daemon/internal/crypto"
)

// offlineDecrypt reproduces an attacker with the user's uid and no daemon.
//
// It is deliberately written from the two artefacts rather than from any Vault
// method: reusing v.decrypt would prove only that the vault can read its own
// rows, which was never in question.
func offlineDecrypt(t *testing.T, dbPath, token string) (string, error) {
	t.Helper()

	account, err := accountForDB(dbPath)
	if err != nil {
		t.Fatalf("resolve keychain account: %v", err)
	}
	dkEncoded, err := keyringGet(keyringService, account)
	if err != nil {
		t.Fatalf("read ML-KEM sk from the credential store: %v", err)
	}
	dk, err := base64.StdEncoding.DecodeString(dkEncoded)
	if err != nil {
		t.Fatalf("decode sk: %v", err)
	}

	// Opened read-only and by path, as a copied file would be.
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open vault.db: %v", err)
	}
	defer db.Close()

	var ctEncoded string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key = 'kem_ciphertext'`).Scan(&ctEncoded); err != nil {
		t.Fatalf("read kem_ciphertext: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ctEncoded)
	if err != nil {
		t.Fatalf("decode kem ciphertext: %v", err)
	}

	var blob []byte
	if err := db.QueryRow(`SELECT encrypted_value FROM vault WHERE token = ?`, token).Scan(&blob); err != nil {
		t.Fatalf("read encrypted row: %v", err)
	}

	ss, err := vaultcrypto.MLKEMDecaps(dk, ct)
	if err != nil {
		return "", err
	}
	key, err := vaultcrypto.DeriveVaultKey(ss)
	if err != nil {
		return "", err
	}
	plain, err := vaultcrypto.Decrypt(key, blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// The default install: keychain half + database half == plaintext, with nothing
// daemon-side in the path.
func TestNoPassphraseVaultDecryptsOffline(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v.db")

	v, err := Open(dbPath, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	secret := "offline-disclosure-" + t.Name()
	token, err := v.Store(secret, "Password", "critical", "agent-1", "tool", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.KeyModeOf() != KeyModeKeychain {
		t.Fatalf("expected the default key mode, got %q", v.KeyModeOf())
	}
	// Closed first: the point is that nothing of akasha's is running.
	v.Close()

	got, err := offlineDecrypt(t, dbPath, token)
	if err != nil {
		t.Fatalf("offline decryption failed — if this is now genuinely impossible, the\n"+
			"claim in docs/THREATMODEL.md and the line `akasha status` prints are both\n"+
			"out of date and must be corrected: %v", err)
	}
	if got != secret {
		t.Fatalf("offline decryption produced %q, want %q", got, secret)
	}
}

// And the reason the passphrase is worth recommending: the same two artefacts
// no longer add up to the key.
func TestPassphraseVaultDoesNotDecryptOffline(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v.db")

	v, err := Open(dbPath, Options{AllowNewVaultKey: true, Passphrase: []byte("correct horse battery staple")})
	if err != nil {
		t.Fatal(err)
	}
	secret := "offline-disclosure-" + t.Name()
	token, err := v.Store(secret, "Password", "critical", "agent-1", "tool", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.KeyModeOf() != KeyModeKeychainPassphrase {
		t.Fatalf("expected the passphrase key mode, got %q", v.KeyModeOf())
	}
	v.Close()

	got, err := offlineDecrypt(t, dbPath, token)
	if err == nil {
		t.Fatalf("a passphrase vault decrypted from the keychain and the database alone "+
			"(recovered %q) — the second factor is not reaching the key", got)
	}
}
