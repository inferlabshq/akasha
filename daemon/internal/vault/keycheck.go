package vault

import (
	"bytes"
	"encoding/base64"
	"fmt"

	vaultcrypto "github.com/inferlabshq/akasha/daemon/internal/crypto"
)

// A WRONG VAULT PASSPHRASE used to open the vault successfully.
//
// The passphrase is folded into the encryption key with Argon2id and nothing
// checked the result, so any passphrase produced *a* key and the daemon started
// on it. Measured: `akasha start --passphrase=WrongPassphraseEntirely` printed
// "passphrase protection enabled" and "daemon started"; `akasha list` showed the
// labels, because labels are metadata and are not encrypted. The mistake only
// surfaced later, on first use, as:
//
//	Error: decrypt: authentication failed
//
// which names neither the passphrase nor the vault. Someone who mistypes their
// passphrase is told their credentials are corrupt.
//
// The fix is a canary: one known plaintext, encrypted under the finished key
// when the key is created, checked on every later open.
//
// This adds no attack surface. An attacker holding the database can already try
// a guess against any real entry — the canary is one more ciphertext under the
// same key, and it is written only where the key material is created, so an
// existing vault can never have a WRONG passphrase baked into its check.
const (
	keyCheckKey       = "key_check"
	keyCheckPlaintext = "akasha-key-check-v1"
)

// writeKeyCheck stores the canary. Called only where key material is created.
func (v *Vault) writeKeyCheck(key []byte) error {
	sealed, err := vaultcrypto.Encrypt(key, []byte(keyCheckPlaintext))
	if err != nil {
		return fmt.Errorf("seal key check: %w", err)
	}
	return v.setMetadata(keyCheckKey, base64.StdEncoding.EncodeToString(sealed))
}

// verifyKey checks the finished key against the canary.
//
// A vault created before this existed has no canary, and that is not an error:
// it opens exactly as it always did. Nothing writes one on its behalf, because
// the only moment the key is known to be right is the moment it is created —
// writing one on first open would enshrine whatever passphrase was typed then,
// which is the bug with an extra step.
func (v *Vault) verifyKey(key []byte, mode KeyMode) error {
	encoded, err := v.getMetadata(keyCheckKey)
	if err != nil || encoded == "" {
		return nil // pre-canary vault, or no check stored
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil // unreadable check is not proof of a wrong key
	}
	got, err := vaultcrypto.Decrypt(key, sealed)
	if err == nil && bytes.Equal(got, []byte(keyCheckPlaintext)) {
		return nil
	}
	if mode == KeyModeKeychainPassphrase {
		return fmt.Errorf("the vault passphrase is wrong.\n" +
			"  Nothing is damaged and nothing was changed — this vault simply did not open.\n" +
			"  It used to open anyway and fail later with `decrypt: authentication failed`,\n" +
			"  which reads like the data is corrupt. It is not; the passphrase is.\n" +
			"  Retry with the right one, or restore the key backup if it is lost.")
	}
	return fmt.Errorf("this vault's key does not match the data in it.\n" +
		"  The key came from this machine's credential store, so the likely causes are a\n" +
		"  restored or replaced keychain entry, or a vault.db from a different install.\n" +
		"  Nothing was changed. Restore the matching key backup before using this vault.")
}
