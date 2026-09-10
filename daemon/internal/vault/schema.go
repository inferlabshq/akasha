package vault

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/inferlabshq/akasha/daemon/internal/buildinfo"
)

// SchemaVersion is the newest database layout this build understands. It is
// stored in the file header (PRAGMA user_version), so it travels with the
// file -- `--export`'s byte copy, a plain cp -- and cannot be confused with a
// data row or clobbered by RestoreKey's bare metadata table.
//
// Before this there was no schema version at all. migrate() was a list of
// CREATE TABLE IF NOT EXISTS, which SQLite treats as a no-op whenever the
// table exists regardless of its columns; so an OLDER build opened a database
// written by a newer one silently, ran its own data migration over it, and
// failed only at the first write that hit a column it did not know. The
// refusal now happens before anything is touched.
const SchemaVersion = 1

// migrations[n] brings a database from version n-1 to n. Index 0 is unused.
// Every step must be idempotent: a crash after a step and before the stamp
// re-runs it on the next open.
//
// Migration 1 is the agent-key id rewrite that used to run unconditionally on
// every open. It becomes the first versioned step so the next schema change
// has somewhere to go.
var migrations = [...]func(*Vault) error{
	1: (*Vault).migrateAgentKeyIDs,
}

func readUserVersion(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&n); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return n, nil
}

// stampSchema records the version the database is now at. PRAGMA takes no
// placeholders; n is an int from this package, never user input.
func (v *Vault) stampSchema(n int) error {
	_, err := v.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", n))
	return err
}

// errSchemaNewer is the refusal for a database written by a build this one
// cannot follow. It names both versions and both fixes; "Nothing was changed"
// is a promise Open keeps by refusing before migrate and before any write.
func errSchemaNewer(path string, found, known int) error {
	return fmt.Errorf("vault %s was written by a newer akasha: schema %d, and this build (%s) understands up to %d.\n"+
		"  Nothing was changed. Run the akasha that wrote it, or upgrade this one (re-run the installer).",
		path, found, buildinfo.Version(), known)
}

// SchemaVersionForDB reads the stored version without opening the vault. Stat
// first, for the reason KeyModeForDB gives: mode=ro does not stop the driver
// creating the file, and a probe must not leave a vault behind.
func SchemaVersionForDB(dbPath string) (int, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return 0, fmt.Errorf("no vault at %s: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(2000)&mode=ro")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	return readUserVersion(db)
}
