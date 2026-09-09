package vault

// `akasha start --passphrase` against a vault that had never had one did not
// fail — it locked the vault. The fold happened, key_mode was written as
// keychain+passphrase, and the canary check then failed; the mode write
// survived, so afterwards BOTH doors were shut: a plain open was refused for
// want of a passphrase, and an open with that same passphrase was refused as
// wrong. The data was never touched and was never recoverable through either
// path.
//
// This matters beyond the bug: `akasha status` now tells a no-passphrase user
// what that means, and a disclosure whose remedy bricks the vault is worse than
// no disclosure at all.

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPassphraseCannotBeAddedToAnExistingVault(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v.db")

	v, err := Open(dbPath, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	secret := "existing-entry-" + t.Name()
	token, err := v.Store(secret, "Password", "critical", "a", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	// The attempt is refused, in terms that name the situation and a way out.
	// Reported rather than fatal, so a regression shows the lockout below too
	// instead of stopping at the wording.
	switch _, err := Open(dbPath, Options{Passphrase: []byte("a new passphrase")}); {
	case err == nil:
		t.Error("adding a passphrase to an existing vault was accepted; it cannot be, " +
			"because the entries are encrypted under the key it would replace")
	case !strings.Contains(err.Error(), "cannot be added"):
		t.Errorf("the refusal does not say what happened:\n%v", err)
	case !strings.Contains(err.Error(), "akasha run"):
		t.Errorf("the refusal names no route that works:\n%v", err)
	}

	// ...and, the part that was actually broken, it changed nothing. The vault
	// still opens the way it always did, and its entries are still readable.
	reopened, err := Open(dbPath, Options{})
	if err != nil {
		t.Fatalf("the vault no longer opens without a passphrase after a refused attempt "+
			"to add one — the refusal wrote something it should not have: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.Retrieve(token, "t")
	if err != nil {
		t.Fatalf("Retrieve after a refused passphrase attempt: %v", err)
	}
	if got != secret {
		t.Fatalf("got %q, want %q", got, secret)
	}
	if mode := reopened.KeyModeOf(); mode != KeyModeKeychain {
		t.Fatalf("key mode is %q after a refused attempt; a failed open must not record "+
			"a protection the key does not have", mode)
	}
}

// The refusal must not reach a vault that genuinely has a passphrase: its owner
// supplies one on every open, and turning that into "cannot be added" would
// lock out the correct usage in the name of fixing the wrong one.
func TestPassphraseVaultStillOpensWithItsPassphrase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v.db")
	pass := []byte("the passphrase this vault was made with")

	v, err := Open(dbPath, Options{AllowNewVaultKey: true, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	token, err := v.Store("kept", "Password", "critical", "a", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	reopened, err := Open(dbPath, Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("reopening a passphrase vault with its passphrase: %v", err)
	}
	defer reopened.Close()
	if got, err := reopened.Retrieve(token, "t"); err != nil || got != "kept" {
		t.Fatalf("Retrieve = %q, %v", got, err)
	}
}

// A vault older than key_mode recording, opened with the passphrase it was made
// with. The mode row says nothing, so the salt is the only evidence the vault
// has a passphrase at all — and reading it as "no passphrase here" would refuse
// the owner's own passphrase.
func TestPreKeyModeVaultWithSaltIsNotTreatedAsKeychainOnly(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v.db")
	pass := []byte("made before key_mode was recorded")

	v, err := Open(dbPath, Options{AllowNewVaultKey: true, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	// Erase the recording, leaving the vault as one created before it existed.
	if _, err := v.db.Exec(`DELETE FROM metadata WHERE key = ?`, keyModeKey); err != nil {
		t.Fatal(err)
	}
	v.Close()

	mode, err := KeyModeForDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode != KeyModeKeychainPassphrase {
		t.Fatalf("KeyModeForDB = %q for a vault with a passphrase salt and no mode row; "+
			"status would tell its owner they have no second factor", mode)
	}
	reopened, err := Open(dbPath, Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("a pre-key_mode passphrase vault was refused its own passphrase: %v", err)
	}
	reopened.Close()
}

// KeyModeForDB is read by `akasha status`, which must not need the key it is
// reporting on: a passphrase vault cannot be opened to ask whether it has a
// passphrase.
func TestKeyModeForDBNeedsNoKey(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain.db")
	v, err := Open(plain, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if mode, err := KeyModeForDB(plain); err != nil || mode != KeyModeKeychain {
		t.Fatalf("KeyModeForDB(plain) = %q, %v", mode, err)
	}

	guarded := filepath.Join(t.TempDir(), "guarded.db")
	gv, err := Open(guarded, Options{AllowNewVaultKey: true, Passphrase: []byte("second factor")})
	if err != nil {
		t.Fatal(err)
	}
	gv.Close()
	if mode, err := KeyModeForDB(guarded); err != nil || mode != KeyModeKeychainPassphrase {
		t.Fatalf("KeyModeForDB(guarded) = %q, %v", mode, err)
	}

	// A path with no vault is not an answer about passphrases.
	if _, err := KeyModeForDB(filepath.Join(t.TempDir(), "absent.db")); err == nil {
		t.Fatal("KeyModeForDB reported a mode for a database that does not exist")
	}

	// The state it is actually called in: `akasha status` runs against a daemon
	// that is holding this database open in WAL mode. A read-only connection to
	// a live WAL is the case where a second reader most easily gets an error
	// instead of an answer — and an error here means status silently says
	// nothing, which is the failure mode the disclosure cannot afford.
	live, err := Open(filepath.Join(t.TempDir(), "live.db"), Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if _, err := live.Store("held open", "Password", "critical", "a", "t", 0); err != nil {
		t.Fatal(err)
	}
	if mode, err := KeyModeForDB(live.dbPath); err != nil || mode != KeyModeKeychain {
		t.Fatalf("KeyModeForDB on a vault the daemon is holding open = %q, %v", mode, err)
	}
}
