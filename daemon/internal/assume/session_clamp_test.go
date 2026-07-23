package assume

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSessionFile is the last line of defense for the arbitrary-file-write
// vector: even if a deliver.name slipped past load-time validation, the write
// must never land outside the session dir. This white-box test drives the sink
// directly with traversal names that Parse would normally reject.
func TestWriteSessionFileRefusesEscape(t *testing.T) {
	base := t.TempDir()
	SetSessionBase(base)
	defer SetSessionBase("")

	dir, err := sessionDir()
	if err != nil {
		t.Fatal(err)
	}
	// A sentinel outside the session dir; no test case may create/overwrite it.
	sentinel := filepath.Join(base, "SHOULD_NOT_EXIST")

	for _, name := range []string{
		"../SHOULD_NOT_EXIST",
		"../../SHOULD_NOT_EXIST",
		"sub/child",
		"nested/../../SHOULD_NOT_EXIST",
	} {
		if _, err := writeSessionFile(dir, name, []byte("pwned"), time.Now().Add(time.Hour)); err == nil {
			t.Errorf("writeSessionFile(%q) should have been refused", name)
		}
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("a traversal escaped the session dir and wrote %s", sentinel)
	}

	// A safe single-component name still works.
	path, err := writeSessionFile(dir, "ok.creds", []byte("x"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("safe name unexpectedly refused: %v", err)
	}
	if filepath.Dir(path) != filepath.Clean(dir) {
		t.Fatalf("safe file written outside session dir: %s", path)
	}
}
