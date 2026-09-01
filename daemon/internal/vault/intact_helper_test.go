package vault

import (
	"database/sql"
	"testing"
)

// writeForeignDB creates a valid SQLite database that is not akasha's.
func writeForeignDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO notes (body) VALUES ('someone else''s data')"); err != nil {
		t.Fatal(err)
	}
}
