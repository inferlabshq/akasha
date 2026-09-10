package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// `akasha status` reads. It must not write, and least of all must it write a
// VAULT.
//
// reportAgentHealth called vault.Open, which creates a database when the path
// has none, so `akasha status --db /somewhere/new` left a 0-byte vault.db at
// whatever path it was handed. Nothing failed and nothing was said; the file was
// simply there afterwards. A 0-byte vault.db is also its own small trap, since
// it is the thing a later open has to decide what to do with.
//
// The assertion is on the filesystem rather than on the output, because the
// defect was invisible in the output.
func TestStatusReportersDoNotCreateAVault(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.db")

	old := dbPath
	t.Cleanup(func() { dbPath = old })
	dbPath = missing

	var buf bytes.Buffer
	reportVaultKey(&buf, missing)
	reportAgentHealth(&buf)

	if _, err := os.Stat(missing); err == nil {
		t.Errorf("a read-only status reporter created %s — status must not write a vault", missing)
	}

	// And the directory it was pointed at stays empty: no journal, no WAL, no
	// sidecar left by a driver that opened something on the way past.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("status left files behind: %v", names)
	}
}
