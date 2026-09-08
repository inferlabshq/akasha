package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// The gate must not wall a user who never protected anything.
//
// This is the risk the design review named as most likely to be wrong: treating
// "the ledger query errored" as "refuse to purge" turns a data-loss bug into a
// cannot-uninstall bug, and the move a walled user makes is `rm -rf`. So the
// refusal has to be narrow — an unopenable vault with NO escrow must still
// purge cleanly, because there is nothing in it that a purge could destroy
// which the user has not already accepted losing.
func TestPurgeIsNotWalledWhenNothingWasEverProtected(t *testing.T) {
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
	// A perfectly ordinary vault: discovered credentials, no escrow.
	tok, err := v.Store("AKIA-not-escrowed", "Credential", "critical", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetLabel("aws:default", tok); err != nil {
		t.Fatal(err)
	}
	acct, err := v.KeychainAccount()
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	deleteKeychainAccountForTest(t, acct) // make it unopenable

	opts := UninstallOptions{
		DataDir: dataDir, DBPath: dbPath,
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
		Purge:      true, Yes: true,
		StopDaemon: func() error { return nil }, DaemonAlive: func() bool { return false },
	}

	out := captureStdout(t, func() {
		if err := Uninstall(opts); err != nil {
			t.Fatalf("a vault with no escrowed files must still purge: %v", err)
		}
	})
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Errorf("the data directory survived a purge that should have run:\n%s", out)
	}
}

// escrowedPaths answers without the key, and refuses rather than guessing.
//
// A wrong "no" here costs the user's only copy of a file, so every failure mode
// must surface as an error and never as an empty list. That polarity is
// inverted from isVaultDB next door, which answers "no" on any failure because
// there a wrong "yes" costs a deleted directory.
func TestEscrowLedgerReadsWithoutTheKeyAndRefusesRatherThanGuessing(t *testing.T) {
	dir := t.TempDir()

	t.Run("finds escrow labels in a LOCKED vault", func(t *testing.T) {
		dbPath := filepath.Join(dir, "locked.db")
		v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true})
		if err != nil {
			t.Fatal(err)
		}
		secretFile := filepath.Join(dir, "s.env")
		if err := os.WriteFile(secretFile, []byte("k=v\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := escrow.Protect(escrow.Direct{Vault: v}, secretFile); err != nil {
			t.Fatal(err)
		}
		acct, _ := v.KeychainAccount()
		v.Close()
		deleteKeychainAccountForTest(t, acct)

		// The vault genuinely will not open...
		if _, err := vault.Open(dbPath, vault.Options{}); err == nil {
			t.Fatal("expected the vault to be unopenable")
		}
		// ...and the ledger still answers, which is the whole point.
		paths, err := escrowedPaths(dbPath)
		if err != nil {
			t.Fatalf("the ledger must work without the key: %v", err)
		}
		if len(paths) != 1 || paths[0] != secretFile {
			t.Errorf("got %v, want [%s]", paths, secretFile)
		}
	})

	t.Run("a vault with no escrow answers empty, not an error", func(t *testing.T) {
		dbPath := filepath.Join(dir, "plain.db")
		v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true})
		if err != nil {
			t.Fatal(err)
		}
		v.Close()
		paths, err := escrowedPaths(dbPath)
		if err != nil {
			t.Fatalf("an ordinary vault must not error: %v", err)
		}
		if len(paths) != 0 {
			t.Errorf("got %v, want none", paths)
		}
	})

	// Damage states. Each must produce an ERROR, never a confident empty list.
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, path string)
	}{
		{"zero-byte file", func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"not a database", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("this is not sqlite"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated mid-header", func(t *testing.T, p string) {
			v, err := vault.Open(p, vault.Options{AllowNewVaultKey: true})
			if err != nil {
				t.Fatal(err)
			}
			v.Close()
			if err := os.Truncate(p, 40); err != nil {
				t.Fatal(err)
			}
		}},
		{"absent entirely", func(t *testing.T, p string) {}},
	} {
		t.Run("refuses on "+tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "vault.db")
			tc.build(t, p)
			paths, err := escrowedPaths(p)
			if err == nil {
				t.Errorf("answered %v with no error — a confident empty list here deletes "+
					"the user's only copy", paths)
			}
			if len(paths) != 0 {
				t.Errorf("returned paths alongside an error: %v", paths)
			}
		})
	}
}

// And the refusal has to be actionable: it names the files, says the vault is
// locked rather than lost, and gives the way out.
func TestPurgeRefusalNamesTheFilesAndTheWayOut(t *testing.T) {
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
	acct, _ := v.KeychainAccount()
	v.Close()
	deleteKeychainAccountForTest(t, acct)

	err = Uninstall(UninstallOptions{
		DataDir: dataDir, DBPath: dbPath,
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
		Purge:      true, Yes: true,
		StopDaemon: func() error { return nil }, DaemonAlive: func() bool { return false },
	})
	if err == nil {
		t.Fatal("purge did not refuse")
	}
	msg := err.Error()
	for _, want := range []string{
		"secrets.env",               // which file
		"LOCKED, not lost",          // the state, in the words that stop a panic
		"akasha vault restore",      // how to get the key back
		"akasha uninstall",          // how to leave without deleting
		"destroy-escrowed-original", // how to abandon one file deliberately
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal should mention %q:\n%s", want, msg)
		}
	}
	if _, statErr := os.Stat(dbPath); statErr != nil {
		t.Errorf("the vault was deleted despite the refusal: %v", statErr)
	}
}

// The other branch of the same contract: the vault OPENED, but a file did not
// come back. A purge may not destroy an original it failed to restore.
//
// Before this, restoreEscrowed printed "recover manually with `akasha restore
// <p>` before purging" and returned nothing — and the purge ran a few lines
// later in the same command, so "before purging" named a window that did not
// exist.
func TestPurgeStopsWhenAnEscrowedFileDoesNotComeBack(t *testing.T) {
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

	// Two files: one restores, one cannot because its directory is gone.
	good := filepath.Join(home, "good.env")
	subdir := filepath.Join(home, "projects", "client-a")
	if err := os.MkdirAll(subdir, 0700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(subdir, "bad.env")
	for _, p := range []string{good, bad} {
		if err := os.WriteFile(p, []byte("K=v\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := escrow.Protect(escrow.Direct{Vault: v}, p); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()
	// The directory the user deliberately removed after protecting.
	if err := os.RemoveAll(filepath.Join(home, "projects")); err != nil {
		t.Fatal(err)
	}

	err = Uninstall(UninstallOptions{
		DataDir: dataDir, DBPath: dbPath,
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
		Purge:      true, Yes: true,
		StopDaemon: func() error { return nil }, DaemonAlive: func() bool { return false },
	})
	if err == nil {
		t.Fatal("purge proceeded despite a file that could not be restored")
	}
	msg := err.Error()
	if !strings.Contains(msg, "bad.env") {
		t.Errorf("the refusal should name the file that failed:\n%s", msg)
	}
	if !strings.Contains(msg, "mkdir -p") {
		t.Errorf("the refusal should name the remedy rather than recreating the directory itself:\n%s", msg)
	}
	if _, statErr := os.Stat(dbPath); statErr != nil {
		t.Errorf("the vault was deleted despite the refusal: %v", statErr)
	}
	// The file that COULD restore is on disk — the message says so, and it must
	// be true, or "nothing has been deleted" would be the only honest wording.
	if got, _ := os.ReadFile(good); escrow.IsStub(got) {
		t.Errorf("the restorable file was not restored before the refusal")
	}
}

// The narrow side of the trade, pinned so nobody widens it by accident.
//
// A file that is not a vault database cannot hold escrow labels, so akasha has
// no basis for claiming it holds someone's only copy — and refusing there would
// wall the person reaching for --purge after a bad disk, who never ran protect
// in their life. The move a walled user makes is rm -rf, which is worse than
// anything this gate prevents.
func TestPurgeIsNotWalledByAFileThatIsNotAVaultDatabase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir := filepath.Join(home, ".akasha")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "vault.db")
	if err := os.WriteFile(dbPath, []byte("corrupt, not sqlite at all"), 0600); err != nil {
		t.Fatal(err)
	}
	// The rest of a real data directory, so purgeGuard recognises it as
	// akasha's and this test is about the escrow gate rather than about the
	// mistyped---db guard next to it.
	for _, marker := range []string{"audit.log", "cli.key"} {
		if err := os.WriteFile(filepath.Join(dataDir, marker), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := Uninstall(UninstallOptions{
		DataDir: dataDir, DBPath: dbPath,
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
		Purge:      true, Yes: true,
		StopDaemon: func() error { return nil }, DaemonAlive: func() bool { return false },
	}); err != nil {
		t.Fatalf("a file that is not a vault database must not wall a purge: %v", err)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Error("the data directory survived a purge that should have run")
	}
}

// NOT TESTED HERE, and the reason is worth writing down: a vault database whose
// escrow ledger cannot be READ is not constructible end-to-end. vault.Open runs
// migrate() (vault.go:209) BEFORE it resolves keys, so a dropped labels table is
// recreated even by an Open that then fails on a missing key — measured. By the
// time the gate asks, the ledger answers "no escrow labels" because the table it
// just lost has been rebuilt empty.
//
// So escrowedPaths' error branch is defensive rather than reachable that way,
// and its polarity is pinned above at the unit level, which is where the
// contract actually lives.

// A dual-factor vault must be able to uninstall.
//
// openVaultForUninstall passed a zero Options, so a keychain+passphrase vault
// hit errPassphraseRequired on every run. That was survivable while a failed
// open merely meant "continue without restoring"; it stopped being survivable
// the moment a failed open began REFUSING the purge, because the users who took
// the strongest protection the product offers would have become the only ones
// who could never uninstall — and their escrowed files the only ones the new
// gate could permanently strand.
func TestDualFactorVaultCanStillUninstall(t *testing.T) {
	const pass = "correct-horse-battery-staple"

	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir := filepath.Join(home, ".akasha")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "vault.db")

	v, err := vault.Open(dbPath, vault.Options{AllowNewVaultKey: true, Passphrase: []byte(pass)})
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
	v.Close()

	base := UninstallOptions{
		DataDir: dataDir, DBPath: dbPath,
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
		Purge:      true, Yes: true,
		StopDaemon: func() error { return nil }, DaemonAlive: func() bool { return false },
	}

	// Without the passphrase the gate holds — which is correct, and is exactly
	// the wall this test exists to prove has a door.
	withoutPass := base
	if err := Uninstall(withoutPass); err == nil {
		t.Fatal("a dual-factor vault holding an escrowed file must not purge without its passphrase")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("the vault was deleted despite the refusal: %v", err)
	}

	// With it, the file comes back and the purge completes.
	withPass := base
	withPass.Passphrase = []byte(pass)
	captureStdout(t, func() {
		if err := Uninstall(withPass); err != nil {
			t.Fatalf("with the passphrase, uninstall must work: %v", err)
		}
	})
	got, err := os.ReadFile(secretFile)
	if err != nil {
		t.Fatalf("the escrowed original is gone: %v", err)
	}
	if string(got) != "API_TOKEN=only-copy\n" {
		t.Errorf("not restored byte-for-byte, got %q", got)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Error("the data directory survived a purge that should have run")
	}
}
