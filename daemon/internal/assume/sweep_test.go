package assume_test

import (
	"os"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

// A file written with a tiny TTL must be swept once its expiry passes, even
// with no further assume call — the background sweeper enforces it.
func TestSweepExpiredRemovesPastTTL(t *testing.T) {
	// Assume with a 1-second TTL.
	res, err := assume.Write("aws", "sweep-test",
		map[string]string{"access_key_id": "AKIA", "secret_access_key": "sk"},
		time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("file should exist immediately after assume: %v", err)
	}

	// Before expiry, a sweep leaves it alone.
	if n := assume.SweepExpired(); n != 0 {
		// Other stale files could exist in a shared dir; only assert our file survives.
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatal("file removed before its TTL elapsed")
	}

	// After expiry, the sweep deletes it.
	time.Sleep(1100 * time.Millisecond)
	assume.SweepExpired()
	if _, err := os.Stat(res.Path); !os.IsNotExist(err) {
		t.Fatalf("expired file should have been swept, stat err=%v", err)
	}
}

// A long-TTL file must NOT be swept prematurely.
func TestSweepExpiredKeepsLiveFile(t *testing.T) {
	res, err := assume.Write("aws", "live-test",
		map[string]string{"access_key_id": "AKIA", "secret_access_key": "sk"},
		time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(res.Path)

	assume.SweepExpired()
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatal("live (1h TTL) file was swept prematurely")
	}
}
