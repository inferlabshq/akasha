package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bug this guard exists for.
//
// `--db` is a global flag with a default, and the data directory is
// filepath.Dir of it — so a typo did not fail, it relocated the deletion.
// Measured before the fix: `akasha uninstall --purge --yes
// --db ~/precious/vault.db` removed ~/precious, which had never held a vault,
// and printed "Akasha fully removed."
func TestPurgeRefusesADirectoryThatIsNotAkashas(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	precious := filepath.Join(home, "precious")
	if err := os.MkdirAll(precious, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(precious, "keepme.txt"), []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Nothing there at all.
	err := purgeGuard(precious, filepath.Join(precious, "vault.db"), false)
	if err == nil {
		t.Fatal("a directory with no vault was accepted for deletion")
	}
	if !strings.Contains(err.Error(), "Nothing has been deleted") {
		t.Errorf("the refusal should say nothing was lost: %v", err)
	}

	// And a file of the right NAME is not a vault. The name is precisely what a
	// typo produces, so it cannot be the thing that authorises a deletion.
	if err := os.WriteFile(filepath.Join(precious, "vault.db"), []byte("not-a-vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := purgeGuard(precious, filepath.Join(precious, "vault.db"), false); err == nil {
		t.Fatal("a non-vault file named vault.db authorised deleting its directory")
	}
}

// A real akasha data directory is still purgeable — the guard must not simply
// break the feature.
func TestPurgeAllowsARealDataDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".akasha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "vault.db")
	if err := os.WriteFile(db, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A corrupt vault is still a vault, and this is exactly when someone
	// reaches for --purge. akasha's own files around it are the proof.
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := purgeGuard(dir, db, true); err != nil {
		t.Fatalf("a real data directory with a damaged vault was refused: %v", err)
	}
}

// The catastrophic shapes, refused by path before anything is looked at.
func TestPurgeRefusesHomeAndShallowPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if reason := undeletable(home); reason == "" {
		t.Error("the home directory itself was not refused — `--db ~/vault.db` would delete it")
	}
	for _, dir := range []string{"/", "/tmp", "/Users", "/home"} {
		if reason := undeletable(dir); reason == "" {
			t.Errorf("%s was not refused", dir)
		}
	}
	// …and an ordinary nested directory is not caught by that net.
	if reason := undeletable(filepath.Join(home, ".akasha")); reason != "" {
		t.Errorf("a normal data directory was refused as undeletable: %s", reason)
	}
}

// macOS per-user temp directories live under /var/folders. An earlier version
// of this guard refused anything under /var and broke the existing uninstall
// tests, which is how that was caught.
func TestPurgeDoesNotRefuseMacOSTempPaths(t *testing.T) {
	if reason := undeletable("/var/folders/xy/abc123/T/akasha-test/.akasha"); reason != "" {
		t.Errorf("a macOS per-user temp path was refused: %s", reason)
	}
}

// The regression that the unit tests missed and the real command found.
//
// vault.Open CREATES the database before failing on anything else, so the first
// version of this guard checked existence AFTER the open and saw a perfectly
// valid akasha vault — one akasha had just made in the wrong directory. The
// original bug went straight through it.
func TestPurgeIgnoresADatabaseAkashaJustCreated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	precious := filepath.Join(home, "precious")
	if err := os.MkdirAll(precious, 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(precious, "vault.db")

	// Stand in for what vault.Open leaves behind: a real, well-formed vault
	// database, in a directory that has nothing to do with akasha.
	if err := os.WriteFile(db, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := purgeGuard(precious, db, false); err == nil {
		t.Fatal("a database created during this very command authorised deleting its directory")
	}
}
