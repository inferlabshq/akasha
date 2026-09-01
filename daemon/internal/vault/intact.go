package vault

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// A database file that ALREADY EXISTS is never a first run, and akasha must not
// present one as if it were.
//
// Measured on a healthy 40-entry vault before this existed:
//
//	truncated to 0 bytes        Open SUCCEEDED, Stats reported 0 entries, no error
//	bytes 20000-28000 zeroed    Open SUCCEEDED, Stats reported 0 entries, no error
//	truncated to 8192 bytes     Open refused: "database disk image is malformed"
//
// Corruption was therefore detectable in one shape and silently presented as a
// fresh, empty, healthy vault in the other two. Nothing warned, either: the
// CLI's "creating a NEW vault" notice is gated on os.Stat, which a 0-byte file
// passes. What the user saw was `status` reporting ok with vault_total 0, and
// `list` answering "Nothing vaulted yet — run `akasha discover all`" — advice
// to overwrite rather than to recover, on a product whose whole job is not
// losing this file.
//
// The two shapes need two detectors, because each is invisible to the other's:
//
//   - A ZEROED file is a perfectly valid empty SQLite database. integrity_check
//     says "ok". What gives it away is that it carries none of akasha's tables.
//     That same signal catches a mistyped --db pointing at an unrelated SQLite
//     file, which used to be silently adopted and migrated into.
//   - A TORN file keeps its schema and its vault_id, so it still looks like
//     akasha's — but integrity_check reports the damaged pages.
//
// Both refuse to open rather than warn. A warning on a path that then answers
// "0 credentials" is a warning the next command talks the user out of.

// vaultTables are the tables whose presence identifies a file as akasha's.
// Any ONE of them is enough: a vault created by an older build has fewer, and
// refusing to open a working vault because it predates a table is the failure
// this file exists to prevent, with the sign flipped.
var vaultTables = []string{"vault", "metadata", "labels", "grants", "profiles", "agent_keys"}

// fileWasThere reports whether dbPath existed BEFORE this process opened it.
// It must be sampled before sql.Open, which creates the file.
func fileWasThere(dbPath string) bool {
	fi, err := os.Stat(dbPath)
	return err == nil && fi.Mode().IsRegular()
}

// checkIntact refuses a database file that exists but is not a healthy akasha
// vault. It is a no-op when the file did not exist, which is the only case that
// is genuinely a first run.
func checkIntact(db *sql.DB, dbPath string, existed bool) error {
	if !existed {
		return nil
	}
	// A zero-length file is its own case, and it gets its own words. It is
	// EMPTY, not damaged: there is nothing in it to recover, so "copy it aside
	// before doing anything" would be advice that costs the reader time and
	// buys them nothing. It is also what a crash between creating the file and
	// writing the first page leaves behind, where deleting it is exactly right.
	// Both readings share one safe next step, so the message can just say it.
	if fi, err := os.Stat(dbPath); err == nil && fi.Size() == 0 {
		return fmt.Errorf(`the vault file at %s is empty (0 bytes), so it was NOT opened.

An empty file is not a vault, and nothing can be recovered from one. It is
either a run that was interrupted before the vault was written, or a vault that
was truncated — and in both cases this file holds nothing either way.

  To restore what you had:   akasha vault restore <backup file>
  To start a new vault here: remove the empty file and run this command again.

akasha stopped rather than reporting a healthy vault with 0 credentials, which
is what it used to do.`, dbPath)
	}
	if err := checkPages(db); err != nil {
		return err
	}
	return checkSchema(db, dbPath)
}

// checkPages runs SQLite's own consistency check. A healthy database answers
// with the single row "ok".
func checkPages(db *sql.DB) error {
	rows, err := db.Query("PRAGMA integrity_check")
	if err != nil {
		return damaged(fmt.Sprintf("the database could not be checked (%v)", err))
	}
	defer rows.Close()

	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return damaged(fmt.Sprintf("the database could not be checked (%v)", err))
		}
		if strings.TrimSpace(line) != "ok" {
			problems = append(problems, strings.TrimSpace(line))
		}
	}
	if err := rows.Err(); err != nil {
		return damaged(fmt.Sprintf("the database could not be checked (%v)", err))
	}
	if len(problems) > 0 {
		// One line is enough to identify the shape; the rest is page detail
		// that helps nobody decide what to do next.
		return damaged("SQLite reports damaged pages: " + problems[0])
	}
	return nil
}

// checkSchema reports whether this file carries any of akasha's tables.
func checkSchema(db *sql.DB, dbPath string) error {
	for _, t := range vaultTables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", t).Scan(&name)
		if err == nil {
			return nil
		}
		if err != sql.ErrNoRows {
			return damaged(fmt.Sprintf("the database could not be read (%v)", err))
		}
	}
	return fmt.Errorf(`%s exists but carries no akasha vault, so it was NOT opened.

Two things look like this, and they want opposite responses:

  A MISTYPED PATH. If you meant to create a new vault, point --db at a path that
  does not exist yet — akasha creates the file, and will not adopt somebody
  else's.

  A VAULT THAT WAS TRUNCATED OR REPLACED. If credentials used to be here, they
  are not in this file any more. Do NOT run `+"`akasha discover`"+` against this path and
  do not delete the file: both overwrite what a recovery would need. Copy it
  aside first, then restore your backup.

akasha will not create a vault over a file that is already there — that is the
check, and it is the reason this stopped instead of reporting an empty vault.`, dbPath)
}

// damaged is the shared refusal for a file that IS akasha's and is broken. The
// wording is deliberate: it names what not to do first, because the two commands
// a person reaches for here — discover, and deleting the file to start clean —
// are both destructive, and the daemon used to recommend the first one.
func damaged(detail string) error {
	return fmt.Errorf(`this vault is damaged and was NOT opened — %s

Your credentials may still be recoverable. Before anything else:

  1. Keep what is left.   cp <vault path> <vault path>.damaged
  2. Restore your backup. akasha vault restore <backup file>

Do NOT run `+"`akasha discover`"+` against this vault and do not delete it. Both
overwrite the file a recovery attempt needs, and an empty vault that reports
success is how this damage stays invisible.`, detail)
}
