package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

// A wrong vault passphrase must be caught at OPEN, not on first use.
//
// It used to open cleanly: the passphrase is folded into the key with Argon2id
// and nothing checked the result, so any passphrase produced a key and the
// daemon started on it. `list` worked too, because labels are metadata and are
// not encrypted. The mistake surfaced later as `decrypt: authentication
// failed`, which tells someone who mistyped their passphrase that their
// credentials are corrupt.
func TestWrongPassphraseIsCaughtAtOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")

	v, err := Open(path, Options{AllowNewVaultKey: true, Passphrase: []byte("correct-horse")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := v.Store("s3cret", "Credential", "critical", "seed", "seed", 0); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// The right one still opens.
	again, err := Open(path, Options{Passphrase: []byte("correct-horse")})
	if err != nil {
		t.Fatalf("the correct passphrase must still open the vault: %v", err)
	}
	again.Close()

	// The wrong one must not.
	bad, err := Open(path, Options{Passphrase: []byte("wrong-entirely")})
	if err == nil {
		bad.Close()
		t.Fatal("a wrong passphrase opened the vault")
	}
	msg := err.Error()
	if !strings.Contains(msg, "passphrase is wrong") {
		t.Errorf("the error must name the passphrase, got: %v", err)
	}
	// The old failure blamed the data. Someone who mistyped needs to know the
	// vault is intact, or they reach for a restore they do not need.
	for _, want := range []string{"Nothing is damaged", "did not open"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error should say %q, got: %v", want, err)
		}
	}
}

// A vault with no passphrase is unaffected, and so is one created before the
// canary existed — it must open exactly as it always did.
func TestKeyCheckDoesNotBreakPlainOrPreCanaryVaults(t *testing.T) {
	dir := t.TempDir()

	plain := filepath.Join(dir, "plain.db")
	v, err := Open(plain, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("create plain: %v", err)
	}
	v.Close()
	reopened, err := Open(plain, Options{})
	if err != nil {
		t.Fatalf("a plain vault must reopen: %v", err)
	}
	reopened.Close()

	// Now strip the canary, which is what every vault created before this looks
	// like, and confirm it still opens rather than being refused.
	pre, err := Open(plain, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pre.db.Exec(`DELETE FROM metadata WHERE key = ?`, keyCheckKey); err != nil {
		t.Fatal(err)
	}
	pre.Close()

	legacy, err := Open(plain, Options{})
	if err != nil {
		t.Fatalf("a vault created before the canary must still open: %v", err)
	}
	legacy.Close()
}
