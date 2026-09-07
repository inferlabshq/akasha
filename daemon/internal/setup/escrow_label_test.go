package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// A restored file's escrow label must go, and must NOT go when the restore did
// not actually land.
//
// escrow.Restore used to leave the entry — "re-protect overwrites it" — so every
// protect/restore round left a permanent escrow label over a file sitting
// untouched on disk. Two costs: an encrypted duplicate of a file the user just
// put back is a stale secret copy, and any later check that asks "does this
// vault hold escrowed originals" sees a name with nothing behind it. A purge
// gate keyed on that would wall a user who tried protect once and changed their
// mind — and the move a walled user makes is `rm -rf`.
func TestUninstallClearsEscrowLabelsOnlyWhenTheFileIsReallyBack(t *testing.T) {
	stage := func(t *testing.T) (*vault.Vault, UninstallOptions, string) {
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
			t.Fatal(err)
		}
		secretFile := filepath.Join(home, "secrets.env")
		if err := os.WriteFile(secretFile, []byte("API_TOKEN=only-copy\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := escrow.Protect(escrow.Direct{Vault: v}, secretFile); err != nil {
			t.Fatal(err)
		}
		return v, UninstallOptions{
			DataDir: dataDir, DBPath: dbPath,
			LogPath:    filepath.Join(dataDir, "audit.log"),
			SocketPath: filepath.Join(dataDir, "akasha.sock"),
			StopDaemon: func() error { return nil }, DaemonAlive: func() bool { return false },
		}, secretFile
	}

	t.Run("a real restore clears the label", func(t *testing.T) {
		v, opts, secretFile := stage(t)

		labels, _ := v.ListLabels(escrow.LabelPrefix)
		if len(labels) != 1 {
			t.Fatalf("expected one escrow label after protect, got %v", labels)
		}
		v.Close()

		captureStdout(t, func() {
			if err := Uninstall(opts); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
		})

		back, err := vault.Open(opts.DBPath, vault.Options{})
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer back.Close()
		if labels, _ := back.ListLabels(escrow.LabelPrefix); len(labels) != 0 {
			t.Errorf("the escrow label survived a successful restore: %v", labels)
		}
		got, _ := os.ReadFile(secretFile)
		if string(got) != "API_TOKEN=only-copy\n" {
			t.Errorf("file not restored byte-for-byte, got %q", got)
		}
	})

	// The half that matters more: a restore that FAILS must leave the vault's
	// copy alone. Dropping it on the strength of Restore's own return value
	// would destroy the only copy on exactly the runs that went wrong.
	//
	// Note what this does NOT construct: a Restore that returns nil while the
	// bytes are absent. Restore writes the envelope it just read, so the
	// on-disk check passes by construction here — that guard earns its keep
	// against a write that silently does not land, and escrow.RestoredOnDisk
	// has its own tests for the comparison itself. Writing a contrived case
	// that made it fire would be testing the mock.
	t.Run("a restore that fails keeps the label", func(t *testing.T) {
		v, opts, secretFile := stage(t)
		label, err := escrow.Label(secretFile)
		if err != nil {
			t.Fatal(err)
		}
		// Not a decodable envelope: Restore refuses before touching the file.
		bad, err := v.Store("not-an-envelope", "EscrowedFile", "critical", "seed", "seed", 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.SetLabel(label, bad); err != nil {
			t.Fatal(err)
		}
		v.Close()

		out := captureStdout(t, func() { _ = Uninstall(opts) })

		back, err := vault.Open(opts.DBPath, vault.Options{})
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer back.Close()
		if labels, _ := back.ListLabels(escrow.LabelPrefix); len(labels) == 0 {
			t.Errorf("the label was dropped even though the restore failed:\n%s", out)
		}
		// And the stub is untouched, so the user can still act on it.
		onDisk, _ := os.ReadFile(secretFile)
		if !escrow.IsStub(onDisk) {
			t.Errorf("a failed restore modified the file on disk")
		}
	})
}
