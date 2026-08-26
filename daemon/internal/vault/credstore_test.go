package vault

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// dbusMissing is what go-keyring actually hands back on a bare Linux box: the
// exec error from trying to start a session bus that isn't installed. It names
// a program the user never asked for and nothing else, which is the whole
// problem — every assertion below is about what akasha adds to it.
var dbusMissing = errors.New(`exec: "dbus-launch": executable file not found in $PATH`)

// withBrokenCredentialStore makes both halves of the store fail the way an
// unusable one does, and restores them afterwards.
func withBrokenCredentialStore(t *testing.T) {
	t.Helper()
	get, set := keyringGet, keyringSet
	t.Cleanup(func() { keyringGet, keyringSet = get, set })
	keyringGet = func(string, string) (string, error) { return "", dbusMissing }
	keyringSet = func(string, string, string) error { return dbusMissing }
}

// remedyPhrases are the things a user cannot get anywhere else. The Secret
// Service requirement appears in no README, no getting-started, no installer
// output and no daemon message; the kill-then-unlock ordering is not
// discoverable from any error at all, because the obvious recovery silently
// does not work once akasha has woken a locked keyring.
var remedyPhrases = []string{
	"Secret Service",
	"gnome-keyring",
	"UNLOCK IT BEFORE",
	"pkill",
	"macOS",
}

func assertNamesTheRemedy(t *testing.T, msg string) {
	t.Helper()
	for _, want := range remedyPhrases {
		if !strings.Contains(msg, want) {
			t.Errorf("the error never mentions %q, so the user is left with a raw D-Bus string:\n%s", want, msg)
		}
	}
}

// GUARANTEE: creating a vault on a machine with no usable credential store
// explains the prerequisite and the fix.
//
// This is the first command a new Linux user runs and the first one that fails.
// It used to report `key setup: store mlkem sk in keychain: exec: "dbus-launch":
// executable file not found in $PATH` and stop there.
func TestNewVaultOnBrokenCredentialStoreNamesTheRemedy(t *testing.T) {
	withBrokenCredentialStore(t)

	// AllowNewVaultKey because the interesting failure is the WRITE. Without it
	// the unreadable-store guard fires first, which is a different (already
	// tested) message about refusing to replace a key that might exist.
	_, err := Open(filepath.Join(t.TempDir(), "v.db"), Options{AllowNewVaultKey: true})
	if err == nil {
		t.Fatal("a vault must not open when its key cannot be stored")
	}
	msg := err.Error()
	assertNamesTheRemedy(t, msg)
	// The reader must not go looking for a backup: nothing was written yet.
	if !strings.Contains(msg, "No vault was created") {
		t.Errorf("the error does not say the vault was not created, so the reader cannot tell "+
			"whether they have lost something:\n%s", msg)
	}
}

// GUARANTEE: the same remedy reaches the path `akasha start` actually takes.
//
// A bare Linux box has no key AND no readable store, so the guard that refuses
// to create a vault over an unreadable one fires before the write does. That
// guard is right to fire and its refusal is well explained — but a user reading
// "start and unlock a Secret Service" still has no way to learn that unlocking
// AFTER akasha has woken a locked keyring does nothing. Both messages carry the
// same remedy so it does not matter which one you land on.
func TestUnreadableStoreGuardNamesTheRemedy(t *testing.T) {
	withBrokenCredentialStore(t)

	_, err := Open(filepath.Join(t.TempDir(), "v.db"), Options{})
	if err == nil {
		t.Fatal("an unreadable credential store must not be treated as an empty one")
	}
	msg := err.Error()
	if !strings.Contains(msg, "refusing to create a new vault") {
		t.Fatalf("the unreadable-store guard did not fire; this test is checking the wrong path:\n%s", msg)
	}
	assertNamesTheRemedy(t, msg)
}

// GUARANTEE: the preflight passes on a healthy store and on a genuinely fresh
// machine, and fails on an unreadable one.
//
// Absence has to pass. A probe that treated "no key yet" as a broken store would
// refuse every first install, which is the only install that matters here.
func TestProbeCredentialStore(t *testing.T) {
	t.Run("healthy store", func(t *testing.T) {
		get := keyringGet
		t.Cleanup(func() { keyringGet = get })
		keyringGet = func(string, string) (string, error) { return "some-key", nil }
		if err := ProbeCredentialStore(); err != nil {
			t.Fatalf("a readable store must pass: %v", err)
		}
	})

	t.Run("fresh machine, no key yet", func(t *testing.T) {
		get := keyringGet
		t.Cleanup(func() { keyringGet = get })
		keyringGet = func(string, string) (string, error) { return "", keyring.ErrNotFound }
		if err := ProbeCredentialStore(); err != nil {
			t.Fatalf("a first install has no key and must still pass: %v", err)
		}
	})

	t.Run("unreadable store", func(t *testing.T) {
		withBrokenCredentialStore(t)
		err := ProbeCredentialStore()
		if err == nil {
			t.Fatal("an unreadable credential store must not pass the preflight")
		}
		assertNamesTheRemedy(t, err.Error())
		if !errors.Is(err, dbusMissing) {
			t.Errorf("the store's own error must survive wrapping, or the cause is unrecoverable "+
				"from a log:\n%s", err)
		}
	})
}

// GUARANTEE: the recovery command the locked-vault error points at carries the
// same remedy as the error that sent you there.
//
// `vault is locked` ends with "if the key really is gone, re-install it from a
// backup: akasha vault restore <file>". On the machine that produced that error
// the credential store is precisely what is broken, so restore is the very next
// thing to fail — and it answered `restore keychain: exec: "dbus-launch":
// executable file not found in $PATH`, a dead end at the end of the recovery
// path akasha's own text routes users down.
func TestRestoreKeyOnBrokenCredentialStoreNamesTheRemedy(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")
	backup := filepath.Join(dir, "key.backup")

	// A genuine backup, taken while the store still worked. The failure under
	// test is the write-BACK, so it has to be reached with a decryptable file
	// rather than short-circuited by a bad passphrase or a bad header.
	v, err := Open(db, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.BackupKey(backup, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	withBrokenCredentialStore(t)

	err = RestoreKey(db, backup, []byte("pw"))
	if err == nil {
		t.Fatal("a restore that could not write the key must not report success")
	}
	msg := err.Error()
	assertNamesTheRemedy(t, msg)
	// This reader has just been told their key may be gone. If the restore also
	// reads as destructive, there is nothing left for them to try.
	if !strings.Contains(msg, "Nothing was changed") {
		t.Errorf("the error does not say the backup and the keychain are unchanged, so the "+
			"reader cannot tell whether re-running is safe:\n%s", msg)
	}
}

// GUARANTEE: the command that MAKES the backup fails the same way.
//
// `vault backup` is what every recovery message tells people to have run
// already, and it is reachable on a broken store — `akasha vault backup` opens
// the vault first, so a machine whose store works well enough to open a vault
// but not to read the key back lands here with no remedy attached.
func TestBackupKeyOnBrokenCredentialStoreNamesTheRemedy(t *testing.T) {
	dir := t.TempDir()
	v, err := Open(filepath.Join(dir, "v.db"), Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	withBrokenCredentialStore(t)

	err = v.BackupKey(filepath.Join(dir, "key.backup"), []byte("pw"))
	if err == nil {
		t.Fatal("a backup that could not read the key must not report success")
	}
	msg := err.Error()
	assertNamesTheRemedy(t, msg)
	// An unreadable store is not a missing key, and saying so is what stops the
	// reader concluding the vault is already lost.
	if !strings.Contains(msg, "No backup was written") {
		t.Errorf("the error does not say the backup was not written:\n%s", msg)
	}
}
