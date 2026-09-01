package vault

import "fmt"

// How the vault key is protected at rest.
//
// The OS keychain exists for exactly one reason: so the daemon can start
// without a human present. It is not a boundary. On Linux the Secret Service
// has no per-caller authorization at all — any process on the session bus can
// request the item — and on macOS the ACL binds to /usr/bin/security rather
// than to akasha, which four differently-signed binaries demonstrated by
// reading a real vault key with no prompt.
//
// So a process running as you can take the keychain half whenever it likes,
// WITHOUT going through the daemon, which means no policy rule and no approval
// prompt is involved. A passphrase is the only half that is stored nowhere.
//
// This is recorded in the vault's own metadata so a mismatch is a sentence
// rather than a decryption failure. It cannot be used to WEAKEN a vault: the
// key is derived from whatever the mode says, so opening a combined vault
// without its passphrase produces a different key and fails on the first
// entry — the mode only decides which explanation the user gets.
type KeyMode string

const (
	// KeyModeKeychain is the default and today's behaviour: the ML-KEM secret
	// key lives in the OS keychain, and the daemon starts unattended.
	KeyModeKeychain KeyMode = "keychain"
	// KeyModeKeychainPassphrase folds an Argon2id passphrase into the vault key.
	// An attacker needs the keychain half AND something stored nowhere, so the
	// direct-keychain bypass no longer opens the vault.
	KeyModeKeychainPassphrase KeyMode = "keychain+passphrase"
)

const keyModeKey = "key_mode"

// KeyModeOf reports how this vault is protected. An unrecorded mode is
// keychain, which is what every vault created before this existed used.
func (v *Vault) KeyModeOf() KeyMode {
	m, err := v.getMetadata(keyModeKey)
	if err != nil || m == "" {
		return KeyModeKeychain
	}
	return KeyMode(m)
}

// setKeyMode records the mode. Called only where the key material is being
// established, so it cannot drift from what the key actually is.
func (v *Vault) setKeyMode(m KeyMode) error {
	return v.setMetadata(keyModeKey, string(m))
}

// RequiresPassphrase reports whether opening this vault needs one.
func (v *Vault) RequiresPassphrase() bool {
	return v.KeyModeOf() == KeyModeKeychainPassphrase
}

// errPassphraseRequired is what a user gets instead of an authentication
// failure on the first entry they touch. The distinction matters: "wrong key"
// reads like a corrupt vault and sends people to `vault restore`, which is the
// one action that could actually lose their data.
func errPassphraseRequired(path string) error {
	return fmt.Errorf(
		"vault %s is protected by a passphrase as well as the OS keychain, and none was given.\n"+
			"  Start it with:  akasha start --passphrase\n"+
			"  (omit the value — you will be prompted, so it never lands in your shell history\n"+
			"  or in /proc, where any process running as you could read it.)\n"+
			"  This is not a damaged vault, and `akasha vault restore` is NOT the fix.",
		path)
}
