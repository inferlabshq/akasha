package vault

import (
	"database/sql"
	"fmt"
	"os"
)

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

const (
	keyModeKey = "key_mode"
	// argon2SaltKey is the salt for the passphrase factor. It is named here
	// rather than beside its one reader because it doubles as EVIDENCE: the
	// only code path that writes it is the passphrase fold, so its presence
	// answers "has this vault ever had a passphrase" for a vault created before
	// key_mode was recorded at all.
	argon2SaltKey = "argon2_salt"
)

// KeyModeOf reports how this vault is protected. An unrecorded mode is
// keychain, which is what every vault created before this existed used.
func (v *Vault) KeyModeOf() KeyMode {
	m, err := v.getMetadata(keyModeKey)
	if err != nil || m == "" {
		return KeyModeKeychain
	}
	return KeyMode(m)
}

// KeyModeForDB reports how the vault at dbPath is protected, without opening
// it.
//
// Opening is not an option for the caller that needs this: `akasha status`
// wants to tell a user whether their vault has a second factor, and a vault
// that HAS one cannot be opened without the passphrase it is asking about. The
// mode is plain metadata, so reading it needs no key.
//
// Errors are the caller's to swallow. A missing or unreadable database is not a
// statement about passphrases, and status must not turn one into a claim.
func KeyModeForDB(dbPath string) (KeyMode, error) {
	// Stat before opening, because "mode=ro" in the DSN does not stop the driver
	// creating the file -- measured, not assumed: `akasha status --db <new path>`
	// left a 0-byte vault.db behind at whatever path it was handed, from a
	// function whose entire job is to READ one.
	//
	// A missing database is a real answer to "what mode is this vault in", and
	// the answer is "there is no vault". Callers already treat an error here as
	// "say nothing", which is the right behaviour for that case too.
	if _, err := os.Stat(dbPath); err != nil {
		return "", fmt.Errorf("no vault at %s: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(2000)&mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()

	var m string
	switch err := db.QueryRow(`SELECT value FROM metadata WHERE key = ?`, keyModeKey).Scan(&m); {
	case err == nil && m != "":
		return KeyMode(m), nil
	case err != nil && err != sql.ErrNoRows:
		return "", err
	}
	// No recorded mode. Before concluding "keychain only" — which is what the
	// caller will PRINT — check the salt, because a vault created with a
	// passphrase before the mode was recorded has one and would otherwise be
	// told its passphrase does not exist.
	var salt string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key = ?`, argon2SaltKey).Scan(&salt); err == nil && salt != "" {
		return KeyModeKeychainPassphrase, nil
	}
	return KeyModeKeychain, nil
}

// hasPassphraseFactor reports whether a passphrase has ever been folded into
// this vault's key — the same question KeyModeForDB answers from a path.
func (v *Vault) hasPassphraseFactor() bool {
	if v.KeyModeOf() == KeyModeKeychainPassphrase {
		return true
	}
	s, err := v.getMetadata(argon2SaltKey)
	return err == nil && s != ""
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

// errPassphraseNotAddable is the refusal for `--passphrase` against a vault
// that has never had one.
//
// Until this existed, that attempt did not refuse — it LOCKED THE VAULT.
// resolveKeys folded the new factor in, recorded key_mode=keychain+passphrase,
// and only then checked the finished key against the canary, which of course no
// longer matched. The mode write survived the failure, so afterwards a plain
// open was refused for want of a passphrase and an open WITH the passphrase was
// refused as "the vault passphrase is wrong" — both doors, on a vault whose
// data was never touched. Measured on a temp vault holding one entry.
//
// The routes below are the ones that work today; naming a passphrase without
// them would leave the reader exactly where the lockout did.
func errPassphraseNotAddable(path string) error {
	return fmt.Errorf(
		"vault %s was created without a passphrase, and one cannot be added to an existing vault.\n"+
			"  Nothing was changed. This vault still opens the way it did, with no --passphrase.\n"+
			"  Adding one means re-encrypting every entry under a new key — that is\n"+
			"  `akasha vault rotate`, which is not implemented yet.\n"+
			"  What does work today:\n"+
			"    akasha run <agent>     runs the agent where neither the keychain key nor\n"+
			"                           vault.db is reachable, which is the exposure a\n"+
			"                           passphrase would close for that agent.\n"+
			"    A NEW vault, created with the passphrase from the start:\n"+
			"      akasha vault backup <file>      # keep the current key first\n"+
			"      akasha start --db <newpath> --passphrase\n"+
			"    and re-vault your credentials there. A passphrase also means typing it at\n"+
			"    every daemon start, so an unattended login-service start no longer works.",
		path)
}
