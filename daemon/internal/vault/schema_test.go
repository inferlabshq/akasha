package vault

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rawDB opens a database with the same driver and no vault logic, for
// building the file states these tests need.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// A database from a newer build is refused with the file untouched. "Nothing
// was changed" is the promise in the error text, and the bytes are the proof:
// the refusal runs before migrate, before the mode is restricted, before the
// keychain is consulted.
func TestNewerSchemaIsRefusedBeforeAnyWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	db := rawDB(t, path)
	if _, err := db.Exec(`CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open(path, Options{AllowNewVaultKey: true})
	if err == nil {
		t.Fatal("a database from a newer build was opened")
	}
	for _, want := range []string{"newer akasha", "schema 99", "understands up to", "upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q: %v", want, err)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("the refused database was modified -- the refusal must come before every write")
	}
}

// Every vault that exists today is unstamped (version 0). It opens, takes the
// whole ladder -- migration 1 really runs, proved by a legacy row it rewrites --
// and is stamped so the next open skips the ladder.
func TestLegacyUnstampedVaultOpensAndIsStamped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	db := rawDB(t, path)
	if _, err := db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_keys (key_id, agent_id, key_hash, created_at, revoked) VALUES ('legacyid', 'a', 'abcdef0123456789', '2026-01-01T00:00:00Z', 0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	v, err = Open(path, Options{})
	if err != nil {
		t.Fatalf("a legacy vault must open: %v", err)
	}
	defer v.Close()
	if got, _ := SchemaVersionForDB(path); got != SchemaVersion {
		t.Errorf("after open, schema = %d, want %d", got, SchemaVersion)
	}
	var id string
	if err := v.db.QueryRow(`SELECT key_id FROM agent_keys WHERE key_hash = 'abcdef0123456789'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "ak_") {
		t.Errorf("migration 1 did not run over the legacy row: key_id = %q", id)
	}
}

// The ladder is shaped correctly and safe to re-run.
func TestMigrationsAreMonotonicAndIdempotent(t *testing.T) {
	if len(migrations)-1 != SchemaVersion {
		t.Fatalf("migrations has %d steps but SchemaVersion is %d", len(migrations)-1, SchemaVersion)
	}
	for n := 1; n <= SchemaVersion; n++ {
		if migrations[n] == nil {
			t.Errorf("migration %d is nil", n)
		}
	}
	v := openTestVault(t)
	if err := v.migrate(0); err != nil {
		t.Fatalf("re-running the whole ladder must be a no-op: %v", err)
	}
	if got, _ := SchemaVersionForDB(v.dbPath); got != SchemaVersion {
		t.Errorf("schema = %d after a re-run, want %d", got, SchemaVersion)
	}
}

// RestoreKey on a missing database leaves a file with only a metadata table.
// That is version 0 and must open and be stamped like any legacy vault.
func TestBareRestoredDBOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	db := rawDB(t, path)
	if _, err := db.Exec(`CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	v, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("a bare metadata-only database must open: %v", err)
	}
	defer v.Close()
	if got, _ := SchemaVersionForDB(path); got != SchemaVersion {
		t.Errorf("schema = %d, want %d", got, SchemaVersion)
	}
}
