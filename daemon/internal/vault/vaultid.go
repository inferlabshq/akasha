package vault

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"

	keyring "github.com/zalando/go-keyring"
)

// Per-vault identity, so two vaults on one machine do not fight over one key.
//
// The keychain entry used to be a single fixed account name — one per install,
// not one per vault. Everything downstream inherited that: creating a second
// vault wrote its key straight over the first one's, and `uninstall --purge`
// deleted "the" key without any way to ask whose it was. The best that could be
// done at purge time was to infer ownership from the vault having opened.
//
// A vault now mints an id when its key material is created and keeps its key at
// `vault-mlkem-sk-<id>`. Ownership stops being an inference: the account name
// says whose key it is, two vaults coexist, and a purge removes exactly one.
//
// LEGACY VAULTS ARE NOT MIGRATED, and that is deliberate. A vault created
// before this has no id and keeps reading the original account name forever.
// Migration would mean copying a key between accounts and deleting the old one
// — a point of no return, in the code path with this project's worst bug
// history, for no benefit the user can see. A vault that already works keeps
// working, byte-for-byte, and only NEW vaults take the new shape. That alone
// removes the collision, because the second vault is always the new one.
const vaultIDKey = "vault_id"

// vaultID returns this vault's id, or "" for a vault created before ids existed.
func (v *Vault) vaultID() string {
	id, err := v.getMetadata(vaultIDKey)
	if err != nil {
		return ""
	}
	return id
}

// ensureVaultID returns this vault's id, minting one if it has none.
//
// Called only where key material is being CREATED. Calling it on an existing
// legacy vault would give it an id while its key stayed at the old account
// name, and the next open would look in the wrong place — which is the one way
// this change could lose a vault.
func (v *Vault) ensureVaultID() (string, error) {
	if id := v.vaultID(); id != "" {
		// Reuse rather than re-mint. A crash between writing the id and writing
		// the key leaves an id with no key; re-minting on the retry would strand
		// the first account name forever.
		return id, nil
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint vault id: %w", err)
	}
	id := hex.EncodeToString(b)
	if err := v.setMetadata(vaultIDKey, id); err != nil {
		return "", fmt.Errorf("store vault id: %w", err)
	}
	return id, nil
}

// keychainAccount is where THIS vault's ML-KEM secret key lives.
func (v *Vault) keychainAccount() string { return accountFor(v.vaultID()) }

// KeychainAccount is keychainAccount for callers outside the package.
//
// `uninstall --purge` reads it BEFORE deleting the data directory: afterwards
// the metadata it is derived from is gone, and a key deleted on the strength of
// a lookup against a removed database would be a guess.
func (v *Vault) KeychainAccount() string { return v.keychainAccount() }

// accountFor maps an id to its keychain account, and "" to the legacy name.
func accountFor(id string) string {
	if id == "" {
		return keyringMLKEMSK
	}
	return keyringMLKEMSK + "-" + id
}

// KeychainProbeFor reports the (service, account) pair the vault at dbPath
// reads its key from, for the sandbox self-test.
//
// Resolved from the database rather than assumed, because the self-test's whole
// job is to prove that THIS vault's key cannot be read from inside the sandbox.
// Probing the wrong account would return "not found" and pass for the wrong
// reason — a green check on a machine where nothing is enforced.
//
// The id is plain metadata, so this needs no key and works on a locked vault.
// Any failure falls back to the legacy account, which is where a vault with no
// id genuinely keeps its key.
func KeychainProbeFor(dbPath string) (service, account string) {
	return keyringService, accountForDB(dbPath)
}

// accountForDB resolves a vault's keychain account straight from its database.
//
// For callers that hold a path rather than an open vault — RestoreKey runs
// before the vault can be opened, since the key it is restoring is the reason
// it cannot be. The id is plain metadata, so no key is needed.
//
// Every failure falls back to the legacy account, which is where a vault with
// no id genuinely keeps its key. That is also the right answer when the
// database is absent: a key restored without one cannot be used regardless,
// because the ciphertext it decapsulates lives in the database.
func accountForDB(dbPath string) string {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(2000)&mode=ro")
	if err != nil {
		return keyringMLKEMSK
	}
	defer db.Close()
	var id string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key = ?`, vaultIDKey).Scan(&id); err != nil {
		return keyringMLKEMSK
	}
	return accountFor(id)
}

// DeleteKeychainAccount removes one specific keychain entry.
//
// Takes the account rather than deriving it, so `uninstall --purge` can capture
// it while the vault is still readable and delete it afterwards. A missing entry
// is success — deletion is the goal.
func DeleteKeychainAccount(account string) error {
	if account == "" {
		return fmt.Errorf("refusing to delete a keychain entry with no account name")
	}
	if err := keyring.Delete(keyringService, account); err != nil && err != keyring.ErrNotFound {
		return err
	}
	return nil
}
