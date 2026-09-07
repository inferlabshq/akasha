package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// What happens to `akasha protect`-escrowed originals when the vault is purged?
//
// protect's whole promise is that the plaintext now exists ONLY in the vault: it
// moves the file in and leaves a comment-only stub naming `akasha restore` as
// the way back. So a purge is the one operation that can destroy the last copy,
// and the question is whether it can do that without the user getting a chance
// to stop it.
func TestPurgeAndEscrowedOriginals(t *testing.T) {
	setup := func(t *testing.T) (UninstallOptions, string, *vault.Vault) {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home)
		dataDir := filepath.Join(home, ".akasha")
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(dataDir, "vault.db")

		v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true})
		if err != nil {
			t.Fatalf("open vault: %v", err)
		}

		secretFile := filepath.Join(home, "secrets.env")
		if err := os.WriteFile(secretFile, []byte("API_TOKEN=the-only-copy\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := escrow.Protect(escrow.Direct{Vault: v}, secretFile); err != nil {
			t.Fatalf("protect: %v", err)
		}
		// The file on disk is now a stub; the bytes live only in the vault.
		onDisk, _ := os.ReadFile(secretFile)
		if !escrow.IsStub(onDisk) {
			t.Fatalf("protect did not leave a stub; this test would prove nothing")
		}

		return UninstallOptions{
			DataDir: dataDir, DBPath: dbPath,
			LogPath:    filepath.Join(dataDir, "audit.log"),
			SocketPath: filepath.Join(dataDir, "akasha.sock"),
			Purge:      true, Yes: true,
			StopDaemon:  func() error { return nil },
			DaemonAlive: func() bool { return false },
		}, secretFile, v
	}

	// THE GOOD PATH: a vault that opens gets its escrowed originals put back
	// before the data directory goes.
	t.Run("a healthy vault restores the original before purging", func(t *testing.T) {
		opts, secretFile, v := setup(t)
		v.Close()

		out := captureStdout(t, func() {
			if err := Uninstall(opts); err != nil {
				t.Fatalf("purge: %v", err)
			}
		})

		got, err := os.ReadFile(secretFile)
		if err != nil {
			t.Fatalf("the escrowed original is gone entirely: %v", err)
		}
		if escrow.IsStub(got) {
			t.Errorf("the file is still a stub after purge:\n%s", out)
		}
		if string(got) != "API_TOKEN=the-only-copy\n" {
			t.Errorf("the original was not restored byte-for-byte, got %q", got)
		}
	})

	// THE PATH THAT MATTERS: the vault cannot be opened — a locked keychain, a
	// key not yet restored — so nothing can be put back. Does the purge stop,
	// or does it delete the only copy anyway?
	t.Run("an unopenable vault must not have its escrowed originals destroyed", func(t *testing.T) {
		opts, secretFile, v := setup(t)
		acct, err := v.KeychainAccount()
		if err != nil {
			t.Fatal(err)
		}
		v.Close()
		// Make the vault unopenable the way a real machine does: the key is not
		// reachable. This is RECOVERABLE — the bytes are still in vault.db, and
		// `akasha vault restore` puts the key back.
		deleteKeychainAccountForTest(t, acct)

		var uerr error
		out := captureStdout(t, func() { uerr = Uninstall(opts) })

		stillThere := true
		if _, err := os.Stat(opts.DBPath); os.IsNotExist(err) {
			stillThere = false
		}
		got, readErr := os.ReadFile(secretFile)

		if !stillThere && readErr == nil && escrow.IsStub(got) {
			t.Errorf("DATA LOSS: the vault was deleted while the file on disk is still a stub.\n"+
				"The escrowed original existed only in that database, the vault was merely LOCKED\n"+
				"rather than lost, and the purge destroyed the recoverable copy.\n"+
				"uninstall returned err=%v and said:\n%s", uerr, out)
		}
	})
}

// deleteKeychainAccountForTest removes this vault's key so the vault will not
// open. Under test the vault uses an in-memory credential store, so nothing on
// the developer's machine is touched.
func deleteKeychainAccountForTest(t *testing.T, account string) {
	t.Helper()
	if err := vault.DeleteKeychainAccount(account); err != nil &&
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("delete key %s: %v", account, err)
	}
}
