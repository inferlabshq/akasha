package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// "This vault has no id" and "the id could not be read" must not be the same
// answer, because accountFor maps the empty one to the SHARED legacy account.
//
// Observed in a macOS test account: `uninstall --purge` reported
//
//	✓ keychain key removed (vault-mlkem-sk)
//
// for a vault that had been created minutes earlier and did carry an id. The
// bare name is where a pre-id vault keeps its key, so on a machine that has one
// this deletes that vault's key, permanently, while reporting success.
func TestUnreadableVaultIDIsNotTreatedAsLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}

	// A vault created now has an id, and resolves to its own account.
	id, err := v.vaultID()
	if err != nil {
		t.Fatalf("a fresh vault should have a readable id: %v", err)
	}
	if id == "" {
		t.Fatal("a fresh vault must mint an id, or two vaults collide on one account")
	}
	acct, err := v.keychainAccount()
	if err != nil {
		t.Fatal(err)
	}
	if acct == keyringMLKEMSK {
		t.Fatalf("a vault with an id resolved to the shared legacy account %q", acct)
	}

	// Now make the lookup FAIL rather than come back empty, which is what a
	// closed or damaged database does.
	v.Close()

	if _, err := v.vaultID(); err == nil {
		t.Error("an unreadable database reported an id lookup as successful")
	}
	if _, err := v.keychainAccount(); err == nil {
		t.Error("keychainAccount guessed an account from an unreadable database")
	}
}

// The other half: a vault that genuinely predates ids must still resolve to the
// legacy account, or every pre-id install stops finding its own key.
func TestAbsentVaultIDStillMeansLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	if _, err := v.db.Exec(`DELETE FROM metadata WHERE key = ?`, vaultIDKey); err != nil {
		t.Fatal(err)
	}
	id, err := v.vaultID()
	if err != nil {
		t.Fatalf("an absent id is a legitimate answer, not an error: %v", err)
	}
	if id != "" {
		t.Fatalf("expected no id, got %q", id)
	}
	acct, err := v.keychainAccount()
	if err != nil {
		t.Fatal(err)
	}
	if acct != keyringMLKEMSK {
		t.Errorf("a pre-id vault must use the legacy account, got %q", acct)
	}
}

// accountForDB has the same two answers and used to flatten them the same way.
func TestAccountForDBSeparatesAbsentFromUnreadable(t *testing.T) {
	dir := t.TempDir()

	// Not a database at all: unreadable, and must not resolve to anything.
	bad := filepath.Join(dir, "not-a-db")
	if err := os.WriteFile(bad, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if acct, err := accountForDB(bad); err == nil {
		t.Errorf("an unreadable file resolved to account %q instead of failing", acct)
	}

	// A real vault with its id removed: absent, and legitimately legacy.
	path := filepath.Join(dir, "vault.db")
	v, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.db.Exec(`DELETE FROM metadata WHERE key = ?`, vaultIDKey); err != nil {
		t.Fatal(err)
	}
	v.Close()

	acct, err := accountForDB(path)
	if err != nil {
		t.Fatalf("a readable pre-id vault is not an error: %v", err)
	}
	if acct != keyringMLKEMSK {
		t.Errorf("pre-id vault should resolve to the legacy account, got %q", acct)
	}
}
