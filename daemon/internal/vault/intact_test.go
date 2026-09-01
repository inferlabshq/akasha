package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// healthyVault builds a real vault with entries in it and returns its path.
func healthyVault(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	for i := 0; i < 40; i++ {
		if _, err := v.Store("SECRET-VALUE", "Credential", "critical", "seed", "seed", 0); err != nil {
			t.Fatal(err)
		}
	}
	if total, _, _ := v.Stats(); total != 40 {
		t.Fatalf("seed: total = %d, want 40", total)
	}
	v.Close()
	return path
}

// The three shapes of damage, and what each one used to do instead.
func TestDamagedVaultIsRefusedNotPresentedAsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, path string)
		want   string
	}{
		{
			// Used to open clean and report 0 entries.
			name: "truncated to zero bytes",
			damage: func(t *testing.T, p string) {
				if err := os.Truncate(p, 0); err != nil {
					t.Fatal(err)
				}
			},
			want: "is empty (0 bytes)",
		},
		{
			// Used to open clean and report 0 entries: a valid schema over
			// unreadable pages.
			name: "torn in the middle",
			damage: func(t *testing.T, p string) {
				f, err := os.OpenFile(p, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.WriteAt(make([]byte, 8000), 20000); err != nil {
					t.Fatal(err)
				}
			},
			want: "damaged",
		},
		{
			// The shape SQLite already caught. Kept so a future change cannot
			// quietly stop catching it.
			name: "truncated mid-page",
			damage: func(t *testing.T, p string) {
				if err := os.Truncate(p, 8192); err != nil {
					t.Fatal(err)
				}
			},
			want: "damaged",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := healthyVault(t)
			// The WAL is part of the database; leaving it would let SQLite
			// replay the vault back into existence and test nothing.
			os.Remove(path + "-wal")
			os.Remove(path + "-shm")
			tc.damage(t, path)

			v, err := Open(path, Options{})
			if err == nil {
				total, _, _ := v.Stats()
				v.Close()
				t.Fatalf("a damaged vault opened cleanly and reported %d entries", total)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should say %q, got: %v", tc.want, err)
			}
			// Whatever it says, it must never point at the command that
			// overwrites the evidence. Naming it as a warning is the point;
			// naming it as a next step is the bug this replaced.
			if msg := err.Error(); strings.Contains(msg, "akasha discover") &&
				!strings.Contains(msg, "Do NOT run `akasha discover`") {
				t.Errorf("discover may only appear as a warning here, got: %v", err)
			}
		})
	}
}

// A mistyped --db pointing at somebody else's SQLite file used to be adopted
// and migrated into.
func TestUnrelatedSQLiteFileIsNotAdopted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.db")
	other, err := Open(path, Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	// Rebuild it as a non-akasha database with its own table.
	os.Remove(path)
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
	writeForeignDB(t, path)

	if _, err := Open(path, Options{AllowNewVaultKey: true}); err == nil {
		t.Fatal("akasha adopted an unrelated SQLite file")
	} else if !strings.Contains(err.Error(), "carries no akasha vault") {
		t.Errorf("the refusal should name the cause, got: %v", err)
	}
}

// The counterpart that keeps the guard honest: a genuine first run, and a
// healthy vault reopened, must both still work.
func TestFirstRunAndReopenAreUnaffected(t *testing.T) {
	path := healthyVault(t)
	v, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("a healthy vault must reopen: %v", err)
	}
	defer v.Close()
	if total, _, _ := v.Stats(); total != 40 {
		t.Fatalf("reopened vault has %d entries, want 40", total)
	}
}
