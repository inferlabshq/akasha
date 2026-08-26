package vault

// White-box tests for branches only reachable with access to internals:
// legacy-cipher migration, the locked-vault guard, the crypto-failure panic,
// and keychain-absent error paths.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"

	vaultcrypto "github.com/inferlabshq/akasha/daemon/internal/crypto"
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

// SQLite creates the database and its WAL with the process umask, so under the
// common 022 the vault ciphertext lands 0644 — readable by every account on the
// machine. Encrypted is not the same as unreadable: the WAL carries the most
// recent writes, and a free copy of the ciphertext can be attacked offline.
func TestOpenRestrictsVaultFileModes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")

	v, err := Open(dbPath, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v.Close()
	if _, err := v.Store("secret", "Credential", "high", "t", "t", 0); err != nil {
		t.Fatalf("Store: %v", err)
	}

	for _, p := range []string{dbPath, dbPath + "-wal"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue // -wal may be checkpointed away; the db itself must exist
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is mode %#o — group/other can read the vault ciphertext", filepath.Base(p), perm)
		}
	}
}

// The guard above this one asks "does a key already exist?" and refuses if so.
// It used to read that answer off `kemErr == nil`, which quietly treated every
// FAILURE to read the keychain as a confident "no key here" — and then minted a
// new one straight over whatever was actually there.
//
// The distinction is not academic. keyring.Get returns ErrNotFound only for
// genuine absence; a locked keychain, a denied ACL prompt, a stopped Secret
// Service or a dead D-Bus each return something else. Every one of those is a
// state where a key may well exist and we simply cannot see it, and the daemon
// meets them routinely — launchd starts it at login, before the login keychain
// is unlocked. Not knowing has to fail exactly like knowing.
func TestOpenRefusesNewVaultWhenKeychainUnreadable(t *testing.T) {
	clearMachineKey(t)
	// Restore the ordinary in-memory keyring for whatever runs next.
	t.Cleanup(func() { keyring.MockInit() })

	// Not ErrNotFound: the store is there, we just cannot read it.
	keyring.MockInitWithError(errors.New("the keychain could not be accessed"))

	_, err := Open(filepath.Join(t.TempDir(), "fresh.db"), Options{})
	if err == nil {
		t.Fatal("an unreadable credential store must not be treated as an empty one")
	}
	// Failing at the guard, not later at keyring.Set, is the whole point: by the
	// time Set runs, the old key is already gone.
	for _, want := range []string{
		"refusing to create a new vault",
		"could not be read",
		"AKASHA_ALLOW_NEW_VAULT",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "could not store the vault key") {
		t.Errorf("reached keyring.Set — the guard did not fire: %v", err)
	}
}

// The counterpart: a genuine first run must still work. ErrNotFound is the one
// error that really does mean "no key on this machine", so it has to stay
// distinguishable from the failures above or the guard would refuse every new
// install on every platform.
func TestOpenAllowsFirstRunWhenKeyGenuinelyAbsent(t *testing.T) {
	clearMachineKey(t)
	v, err := Open(filepath.Join(t.TempDir(), "first.db"), Options{})
	if err != nil {
		t.Fatalf("a genuine first run must still create a vault: %v", err)
	}
	defer v.Close()
	tok, err := v.Store("hello", "APIKey", "low", "a", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.Retrieve(tok, "t"); err != nil || got != "hello" {
		t.Fatalf("new vault does not round-trip: %q %v", got, err)
	}
}

// The locked-vault message used to name exactly one cause — "the akasha binary
// was replaced/re-signed" — and send the user to `akasha vault restore`. That
// is the macOS diagnosis. On Linux the overwhelmingly likely cause is a Secret
// Service that is not running or not unlocked, where the key is intact and
// restoring from a backup is the wrong move to be recommending. Both platforms
// have to be named, the same way the sibling new-vault guard names them.
func TestLockedVaultErrorNamesBothPlatforms(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")

	v, err := Open(db, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	keyring.Delete(keyringService, keyringMLKEMSK) // key gone, ciphertext stays

	_, err = Open(db, Options{AllowNewVaultKey: true})
	if err == nil {
		t.Fatal("expected locked-vault error when the keychain key is missing")
	}
	msg := err.Error()
	for _, want := range []string{"Linux", "Secret Service", "macOS"} {
		if !strings.Contains(msg, want) {
			t.Errorf("locked-vault error never mentions %q, so one platform's users are sent "+
				"to diagnose the other platform's problem:\n%s", want, msg)
		}
	}
}

// The macOS half of the new-vault guard, which errors.Is could not close.
//
// go-keyring's darwin backend shells out to /usr/bin/security and maps ANY
// output containing "could not be found" to ErrNotFound — and the CLI says that
// both for a missing item and for a keychain it cannot reach. So an unreachable
// login keychain reports itself as a fresh machine, and this is the branch that
// mints a key over the real one. launchd starts the daemon in exactly that
// state at login, before the keychain is unlocked.
//
// Modelled by a store that answers ErrNotFound to reads and fails everything
// else — the shape of an unreachable keychain seen through that mapping.
func TestOpenRefusesNewVaultWhenTheStoreOnlyLooksEmpty(t *testing.T) {
	clearMachineKey(t)

	realGet, realSet, realDelete := keyringGet, keyringSet, keyringDelete
	t.Cleanup(func() { keyringGet, keyringSet, keyringDelete = realGet, realSet, realDelete })

	unreachable := errors.New("keychain could not be accessed")
	keyringGet = func(service, account string) (string, error) {
		return "", keyring.ErrNotFound // "absent", indistinguishable from fresh
	}
	keyringSet = func(service, account, secret string) error { return unreachable }
	keyringDelete = func(service, account string) error { return unreachable }

	_, err := Open(filepath.Join(t.TempDir(), "fresh.db"), Options{})
	if err == nil {
		t.Fatal("a store that reports absence but cannot be written must not be treated as a fresh machine")
	}
	for _, want := range []string{"not answering reliably", "was NOT generated", "AKASHA_ALLOW_NEW_VAULT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// The counterpart that keeps the probe honest: a store that genuinely works and
// genuinely has no key must still allow a first run, or every new install on
// every platform would be refused.
func TestOpenAllowsFirstRunWhenTheStoreRoundTrips(t *testing.T) {
	clearMachineKey(t)
	if err := StoreIsReachable(); err != nil {
		t.Fatalf("the in-memory test keyring should round-trip: %v", err)
	}
	v, err := Open(filepath.Join(t.TempDir(), "first.db"), Options{})
	if err != nil {
		t.Fatalf("a genuine first run must still create a vault: %v", err)
	}
	defer v.Close()
}

// The probe must not leave its canary behind in the store it just tested.
func TestStoreIsReachableCleansUpAfterItself(t *testing.T) {
	if err := StoreIsReachable(); err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if _, err := keyringGet(keyringService, probeAccount); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("probe left its canary behind (err=%v)", err)
	}
}

// The new-vault guard's door, reached from the other side.
//
// That guard refuses to MINT a key over an existing one. RestoreKey walked
// straight to keyringSet with no check at all, so `akasha vault restore` did the
// same damage by the other route — and it is the command every recovery message
// points at, so it gets run by people who have just been told their key may be
// gone. The vault the old key belonged to becomes permanently undecryptable, and
// a running daemon keeps working from memory until the next restart.
func TestRestoreKeyRefusesToOverwriteADifferentKey(t *testing.T) {
	dir := t.TempDir()
	clearMachineKey(t)

	// Vault A: the machine's live vault, and the key currently in the store.
	a, err := Open(filepath.Join(dir, "a.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Store("vault-a-secret", "APIKey", "critical", "x", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	backupA := filepath.Join(dir, "a.akb")
	if err := a.BackupKey(backupA, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	a.Close()

	// Vault B's backup, taken from a DIFFERENT key — the file someone carries
	// over from another machine.
	clearMachineKey(t)
	b, err := Open(filepath.Join(dir, "b.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "b.akb")
	if err := b.BackupKey(backup, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	b.Close()

	// Put vault A's key back — through its own backup, since the store is now
	// empty and only that file still holds the key. This is the ordinary
	// nothing-present restore, and it must be allowed.
	clearMachineKey(t)
	if err := RestoreKey(filepath.Join(dir, "a.db"), backupA, []byte("pw")); err != nil {
		t.Fatalf("restoring onto an empty store should be allowed: %v", err)
	}

	err = RestoreKey(filepath.Join(dir, "b.db"), backup, []byte("pw"))
	if err == nil {
		t.Fatal("restoring over a different key must not silently replace it")
	}
	for _, want := range []string{"DIFFERENT vault key", "permanently", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}

	// The refusal has to be real: vault A must still decrypt.
	reopened, err := Open(filepath.Join(dir, "a.db"), Options{})
	if err != nil {
		t.Fatalf("vault A no longer opens after the refusal: %v", err)
	}
	defer reopened.Close()
	if got, err := reopened.Retrieve(tok, "t"); err != nil || got != "vault-a-secret" {
		t.Fatalf("vault A no longer decrypts: %q %v", got, err)
	}
}

// --force is the escape hatch, and it does exactly what it warns about.
func TestRestoreKeyForceReplacesTheExistingKey(t *testing.T) {
	dir := t.TempDir()
	clearMachineKey(t)

	b, err := Open(filepath.Join(dir, "b.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "b.akb")
	if err := b.BackupKey(backup, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	b.Close()

	clearMachineKey(t)
	a, err := Open(filepath.Join(dir, "a.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	a.Close()

	if err := RestoreKey(filepath.Join(dir, "b.db"), backup, []byte("pw"),
		RestoreOptions{ReplaceExistingKey: true}); err != nil {
		t.Fatalf("--force should permit the replacement: %v", err)
	}
	if _, err := Open(filepath.Join(dir, "b.db"), Options{}); err != nil {
		t.Errorf("vault B should open on its restored key: %v", err)
	}
}

// Restoring the key that is ALREADY there is the ordinary case — a re-run after
// fixing the store, or a belt-and-braces recovery — and must not be refused.
func TestRestoreKeyAcceptsTheSameKeyItAlreadyHas(t *testing.T) {
	dir := t.TempDir()
	clearMachineKey(t)

	v, err := Open(filepath.Join(dir, "v.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "v.akb")
	if err := v.BackupKey(backup, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	if err := RestoreKey(filepath.Join(dir, "v.db"), backup, []byte("pw")); err != nil {
		t.Fatalf("restoring the key already in the store must be a no-op, got: %v", err)
	}
}

// The DATABASE half of a restore, which was unguarded in every branch.
//
// Guarding the keychain alone left the worse door open: restoring the wrong
// backup onto a machine whose store happens to be EMPTY passed every check —
// nothing was being replaced — and then overwrote kem_ciphertext anyway. The
// vault opened and decrypted nothing. rc=0, a green tick, every entry
// unreadable. It is also the likeliest command to be run in that state, because
// "vault is locked" points at it.
func TestRestoreKeyRefusesToOrphanEntriesInTheTargetVault(t *testing.T) {
	dir := t.TempDir()
	clearMachineKey(t)

	// Vault V, with an entry, and its own backup.
	v, err := Open(filepath.Join(dir, "v.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := v.Store("the-real-secret", "APIKey", "critical", "a", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	backupV := filepath.Join(dir, "v.akb")
	if err := v.BackupKey(backupV, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	v.Close()
	vCT := kemCiphertextOf(t, filepath.Join(dir, "v.db"))

	// A backup from a DIFFERENT vault entirely.
	clearMachineKey(t)
	other, err := Open(filepath.Join(dir, "other.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(dir, "other.akb")
	if err := other.BackupKey(wrong, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	other.Close()

	// The store is now EMPTY, so the keychain half has nothing to object to.
	// Only the DB half can catch this.
	clearMachineKey(t)
	err = RestoreKey(filepath.Join(dir, "v.db"), wrong, []byte("pw"))
	if err == nil {
		t.Fatal("restoring a foreign key onto a populated vault must not report success")
	}
	for _, want := range []string{"DIFFERENT key", "unreadable", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}

	// And it has to be a REAL refusal. Reopening the vault would only prove the
	// fixture cleared the key, so read the thing the restore would have
	// overwritten: V's kem_ciphertext must be untouched, and the entry must
	// still decrypt once V's own key is back.
	if after := kemCiphertextOf(t, filepath.Join(dir, "v.db")); after != vCT {
		t.Fatalf("the refused restore rewrote kem_ciphertext anyway:\n  before %s\n  after  %s", vCT, after)
	}
	if err := RestoreKey(filepath.Join(dir, "v.db"), backupV, []byte("pw")); err != nil {
		t.Fatalf("V's own backup should restore cleanly after the refusal: %v", err)
	}
	reopened, err := Open(filepath.Join(dir, "v.db"), Options{})
	if err != nil {
		t.Fatalf("vault V no longer opens: %v", err)
	}
	defer reopened.Close()
	if got, err := reopened.Retrieve(tok, "t"); err != nil || got != "the-real-secret" {
		t.Fatalf("vault V no longer decrypts: %q %v", got, err)
	}
}

// kemCiphertextOf reads the metadata row a restore would overwrite, without
// needing the key that would open the vault.
func kemCiphertextOf(t *testing.T, dbPath string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ct string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key = 'kem_ciphertext'`).Scan(&ct); err != nil {
		t.Fatalf("reading kem_ciphertext: %v", err)
	}
	return ct
}

// A backup that decrypts is not yet a backup that contains anything. An empty
// mlkem_sk installed cleanly and then refused the CORRECT backup afterwards,
// because by then the store held a key — a recovery that destroys the next
// attempt at recovery.
func TestRestoreKeyRejectsABackupWithNoKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	clearMachineKey(t)

	// A well-formed, correctly-encrypted backup whose payload is empty.
	empty := filepath.Join(dir, "empty.akb")
	writeBackupWithMaterial(t, empty, []byte("pw"), map[string]string{})

	if err := RestoreKey(filepath.Join(dir, "v.db"), empty, []byte("pw")); err == nil {
		t.Fatal("a backup with no key material must not be installed")
	} else if !strings.Contains(err.Error(), "key material") {
		t.Errorf("error should say what is missing, got: %v", err)
	}

	// The store must be untouched, so a correct backup still works afterwards.
	if _, err := keyringGet(keyringService, keyringMLKEMSK); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("a refused restore left something in the store (err=%v)", err)
	}
}

// writeBackupWithMaterial writes a well-formed, correctly-encrypted backup whose
// PAYLOAD is whatever the caller says — the shape BackupKey produces, without
// requiring a vault to produce it. It exists so the contents check can be tested
// on a file that decrypts perfectly and still carries nothing.
func writeBackupWithMaterial(t *testing.T, path string, passphrase []byte, m map[string]string) {
	t.Helper()
	material, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := vaultcrypto.NewArgon2Salt()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vaultcrypto.Encrypt(
		vaultcrypto.DerivePassphraseKey(passphrase, salt, vaultcrypto.DefaultArgon2Params), material)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte{1}, append(salt, sealed...)...)
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatal(err)
	}
}
