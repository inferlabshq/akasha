package assume_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

// Every Write in this package puts a real plaintext credential on disk, so the
// default location this binary resolves is itself worth asserting: TestMain's
// temp home, which it deletes on the way out.
//
// Redirecting HOME is not enough to get that, which is the trap this test
// exists to hold shut. HOME is the LAST candidate — on Linux $XDG_RUNTIME_DIR
// and /dev/shm are tried first — so a package that looks isolated on a Mac
// writes its credential files into a tmpfs directory shared with every other
// process on the host, and leaves them there.
func TestWriteLandsInsideTheTestHome(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Fatal("TestMain should have pointed HOME at a temp dir")
	}
	res, err := assume.Write("aws", "isolation-check", map[string]string{
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secretvalue123",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(res.Path)

	if !strings.HasPrefix(res.Path, home+string(os.PathSeparator)) {
		t.Fatalf("a plaintext credential file was written to %s, outside the test home %s", res.Path, home)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("the path returned is not where the file went: %v", err)
	}
}
