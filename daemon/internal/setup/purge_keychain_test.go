package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// --purge must delete THIS vault's keychain entry, and nothing else's.
//
// It did not. The account name is read from metadata inside the database, and
// the read happened 78 lines AFTER the handle was closed — so it failed every
// time with "sql: database is closed", silently, because the fallback was the
// shared legacy account name. Every purge deleted `vault-mlkem-sk` regardless
// of which vault it was purging: orphaning the real key on a one-vault machine,
// and destroying an OLDER vault's key on a machine with two.
//
// The second case is the one this test is shaped around, because it is the one
// that loses data belonging to something the user was not uninstalling.
func TestPurgeDeletesThisVaultsKeyAndNotTheLegacyOne(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dataDir := filepath.Join(home, ".akasha")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "vault.db")

	v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	mine, err := v.KeychainAccount()
	if err != nil {
		t.Fatalf("resolve this vault's account: %v", err)
	}
	v.Close()

	service, _ := vault.KeychainProbeFor(dbPath)
	if _, err := keyring.Get(service, mine); err != nil {
		t.Fatalf("this vault's key should exist at %q: %v", mine, err)
	}

	// An OLDER vault on the same machine: its key lives at the shared,
	// pre-id account name. Purging the vault above must not touch it.
	legacy := strings.TrimSuffix(mine, mine[strings.LastIndex(mine, "-"):])
	if legacy == mine {
		t.Fatalf("could not derive the legacy account name from %q", mine)
	}
	if err := keyring.Set(service, legacy, "another-vaults-key"); err != nil {
		t.Fatalf("plant legacy key: %v", err)
	}

	opts := UninstallOptions{
		DataDir: dataDir, DBPath: dbPath,
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
		Purge:      true, Yes: true,
		StopDaemon:  func() error { return nil },
		DaemonAlive: func() bool { return false },
	}
	out := captureStdout(t, func() {
		if err := Uninstall(opts); err != nil {
			t.Fatalf("purge: %v", err)
		}
	})

	if _, err := keyring.Get(service, mine); err == nil {
		t.Errorf("this vault's own key survived the purge (%s):\n%s", mine, out)
	}
	if got, err := keyring.Get(service, legacy); err != nil || got != "another-vaults-key" {
		t.Errorf("PURGE DESTROYED ANOTHER VAULT'S KEY at %q (err=%v):\n%s", legacy, err, out)
	}
	if strings.Contains(out, "could not determine which entry") {
		t.Errorf("the account was unresolvable at delete time — the handle closed too early:\n%s", out)
	}
	if !strings.Contains(out, mine) {
		t.Errorf("the report should name the account it removed (%s):\n%s", mine, out)
	}
}
