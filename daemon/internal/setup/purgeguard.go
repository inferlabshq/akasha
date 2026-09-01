package setup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // same pure-Go driver the vault uses
)

// What `--purge` is allowed to delete, and whose keychain key it may remove.
//
// The data directory is derived as filepath.Dir(--db), and --db is a global
// flag with a default. So a mistyped path did not fail — it relocated the
// deletion. `akasha uninstall --purge --yes --db ~/precious/vault.db` removed
// ~/precious, a directory that had never held a vault, and reported "Akasha
// fully removed". `--db ~/vault.db` would have taken the home directory.
//
// These are TWO questions, and conflating them was the first fix's mistake:
//
//   - May I delete this directory? Needs proof it is an akasha data directory.
//     A vault that will not open is still a vault, and a user whose keyring is
//     broken must still be able to clean up.
//   - May I delete the machine's keychain key? Needs proof it is THIS vault's.
//     The entry is global — one per install, not one per vault — so removing it
//     for a vault we could not open could take the key another vault needs.
//
// The first is answered structurally, without a key: an akasha vault is a
// SQLite database with a `vault` table. The second is answered by the vault
// having opened, which is the only available proof that the key matches.

// purgeGuard reports why the DATA DIRECTORY must not be deleted, or nil.
//
// dbExisted must be sampled BEFORE the vault is opened. vault.Open CREATES the
// database and its schema before it fails on anything else, so by the time this
// runs there is a perfectly valid akasha vault sitting in whatever directory
// --db pointed at — one akasha made itself, seconds ago. Checking existence
// after the fact meant the first version of this guard let the original bug
// straight through: ~/precious was still deleted, because ~/precious/vault.db
// now existed and had the right schema.
//
// Nothing may authorise a deletion on the strength of a file the deleting
// program just created.
func purgeGuard(dataDir, dbPath string, dbExisted bool) error {
	clean := filepath.Clean(dataDir)

	if !dbExisted {
		return fmt.Errorf(
			"refusing to purge %s: there was no vault at %s when this command started.\n"+
				"  Nothing has been deleted. Check the --db path — the directory that gets\n"+
				"  removed is the one CONTAINING it.",
			shorten(clean), shorten(dbPath))
	}

	if reason := undeletable(clean); reason != "" {
		return fmt.Errorf(
			"refusing to purge %s: %s.\n"+
				"  Nothing has been deleted. The data directory is taken from `--db`, so a vault\n"+
				"  kept directly in such a directory would have this command delete the whole\n"+
				"  thing. Keep the vault in a directory of its own.",
			shorten(clean), reason)
	}
	// Either the database really is a vault, or the directory around it is
	// unmistakably akasha's. The second clause exists for a CORRUPT vault — a
	// truncated or zero-length file after a bad disk — which is exactly when
	// someone reaches for --purge and is not a moment to refuse them. What it
	// still rejects is the case that caused this guard: a --db typo pointing at
	// a directory that has nothing to do with akasha.
	if !isVaultDB(dbPath) && !looksLikeDataDir(clean) {
		return fmt.Errorf(
			"refusing to purge %s: %s is not an akasha vault database, and %s holds none of\n"+
				"  akasha's other files either.\n"+
				"  Nothing has been deleted. Check the --db path — the directory that gets\n"+
				"  removed is the one CONTAINING it.",
			shorten(clean), shorten(dbPath), shorten(clean))
	}
	return nil
}

// looksLikeDataDir reports whether dir holds files only akasha puts there.
//
// The fallback for a vault too damaged to identify by its schema. Deliberately
// requires akasha's OWN artifacts rather than the presence of a vault.db, since
// the name is what a typo produces.
func looksLikeDataDir(dir string) bool {
	for _, marker := range []string{
		"audit.log", "cli.key", "policy.yaml", "templates.dist", "templates", "sessions",
	} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

// isVaultDB reports whether path is a SQLite database with akasha's own schema.
//
// Read-only and key-free on purpose: this must answer for a vault whose keyring
// is broken, which is exactly when a user reaches for --purge. Any failure is
// a "no" — the consequence of a wrong answer here is a deleted directory.
func isVaultDB(path string) bool {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(2000)&mode=ro")
	if err != nil {
		return false
	}
	defer db.Close()
	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='vault'`).Scan(&name)
	return err == nil && name == "vault"
}

// undeletable names the directories a purge must never remove wholesale, or ""
// when the path is unremarkable.
//
// Deliberately short. An earlier version also refused anything under /var,
// /usr, /opt and friends, which is wrong on macOS — a per-user temp directory
// lives under /var/folders — and it failed the existing uninstall tests for
// that exact reason. The cases that actually matter are the home directory
// itself and anything shallow enough to belong to the system.
func undeletable(dir string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if h := filepath.Clean(home); dir == h {
			return "that is your home directory"
		}
	}
	if dir == "/" || dir == "." || dir == "" {
		return "that is the filesystem root"
	}
	// Fewer than two separators means /a — a top-level directory, never a place
	// a vault should be purged from.
	if strings.Count(strings.TrimSuffix(dir, "/"), "/") < 2 {
		return "that is a top-level directory (" + dir + ")"
	}
	return ""
}
