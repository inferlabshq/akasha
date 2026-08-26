package setup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// stubExportPassphrase replaces the terminal reader. The real one needs a TTY,
// so without this the result of these tests would depend on how the test binary
// was launched.
func stubExportPassphrase(t *testing.T, pass []byte) {
	t.Helper()
	prev := readExportPassphrase
	readExportPassphrase = func(string) []byte { return pass }
	t.Cleanup(func() { readExportPassphrase = prev })
}

// GUARANTEE: --export writes nothing at all unless it can produce a whole
// bundle. It used to copy vault.db first and only then discover it had no
// terminal to read a passphrase from, so a scripted uninstall left a directory
// that looks like a backup, holds no key — and, because the vault was still
// open, holds no rows either. Then it aborted the uninstall.
func TestUninstallExportRefusesWithoutWritingAnything(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	escrowAWSCreds(t, home, opts)
	stubExportPassphrase(t, nil) // no terminal → no passphrase

	opts.ExportDir = filepath.Join(home, "bundle")
	opts.Purge, opts.Yes = true, true

	var err error
	captureStdout(t, func() { err = Uninstall(opts) })
	if err == nil {
		t.Fatal("export with no way to read a passphrase must fail")
	}

	if entries, rerr := os.ReadDir(opts.ExportDir); rerr == nil {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("a failed export left %v behind — it looks like a backup and is not one", names)
	}

	// ...and the refusal has to happen before anything destructive.
	if _, serr := os.Stat(opts.DataDir); serr != nil {
		t.Fatalf("a failed export must abort the uninstall, not purge anyway: %v", serr)
	}
}

// GUARANTEE: the exported vault.db, on its own, really is the vault.
//
// The bundle is copied out of a vault that is still open, and in WAL mode that
// means every row is in vault.db-wal, not in vault.db. The bundle shipped 0
// rows: `akasha vault restore` would put the key back and the user would find
// an empty vault and an escrow stub where their credentials used to be.
func TestUninstallExportBundleHoldsTheEscrowedOriginal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	escrowAWSCreds(t, home, opts)
	stubExportPassphrase(t, []byte("export-passphrase"))

	opts.ExportDir = filepath.Join(home, "bundle")

	var err error
	captureStdout(t, func() { err = Uninstall(opts) })
	if err != nil {
		t.Fatalf("Uninstall --export: %v", err)
	}
	for _, name := range []string{"vault.db", "akasha-backup.akb"} {
		if _, serr := os.Stat(filepath.Join(opts.ExportDir, name)); serr != nil {
			t.Fatalf("bundle is missing %s: %v", name, serr)
		}
	}

	// Clobber the restored original, then rebuild it from the BUNDLE alone.
	// That is the only assertion that distinguishes a real backup from a file
	// of the right name.
	credsPath := filepath.Join(home, ".aws/credentials")
	if werr := os.WriteFile(credsPath, []byte("clobbered\n"), 0600); werr != nil {
		t.Fatal(werr)
	}

	// The keychain subprocess blocks under a faked $HOME, so the copy is opened
	// with the real one restored — same dance as escrowAWSCreds.
	fake := os.Getenv("HOME")
	os.Setenv("HOME", realHome)
	bundled, oerr := vault.Open(filepath.Join(opts.ExportDir, "vault.db"), vault.Options{})
	os.Setenv("HOME", fake)
	if oerr != nil {
		t.Fatalf("the exported vault.db is not a vault — the write-ahead log was never "+
			"folded into it, so this bundle is empty: %v", oerr)
	}
	defer bundled.Close()

	if rerr := escrow.Restore(escrow.Direct{Vault: bundled}, credsPath); rerr != nil {
		t.Fatalf("the exported vault.db holds no escrowed original: %v", rerr)
	}
	mustEqualFile(t, credsPath, fakeAWSCreds)
}

// holdVaultReader parks a second connection to dbPath in a read transaction.
// SQLite cannot truncate a write-ahead log out from under a reader, so every
// checkpoint taken while this is held reports busy — which is what a second
// akasha process (a `status`, a backup, a stray daemon) does to an export in
// real life.
func holdVaultReader(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	// A deferred transaction takes no lock until it actually reads.
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM vault`).Scan(&n); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback(); db.Close() })
}

// GUARANTEE: when the write-ahead log cannot be folded into vault.db, --export
// refuses and writes NOTHING — not even the DB copy it takes first.
//
// This is the other half of the empty-bundle bug. A checkpoint that reports
// busy means recent writes are still stranded in vault.db-wal, so the copy
// about to be taken is silently short of them: a bundle that looks complete,
// restores, and is missing exactly the credentials most recently protected.
// Since a bundle is only ever opened on the day it is needed, refusing is the
// only safe answer, and refusing has to mean nothing on disk.
func TestUninstallExportRefusesWhenTheWALCannotBeFolded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	escrowAWSCreds(t, home, opts)
	stubExportPassphrase(t, []byte("export-passphrase"))

	vlt, err := openVaultForUninstall(opts.DBPath) // the handle escrowAWSCreds opened
	if err != nil {
		t.Fatal(err)
	}
	holdVaultReader(t, opts.DBPath)

	dir := filepath.Join(home, "bundle")
	err = exportBundle(vlt, opts.DBPath, dir)
	if err == nil {
		t.Fatal("export must refuse while the write-ahead log cannot be folded in — " +
			"the vault.db it would copy is missing the most recent writes")
	}
	if !strings.Contains(err.Error(), "write-ahead frames") {
		t.Fatalf("the refusal has to say the copy would be incomplete, got: %v", err)
	}

	if _, serr := os.Stat(dir); !os.IsNotExist(serr) {
		t.Fatalf("a refused export left %s behind — it looks like a backup and is not one", dir)
	}
}
