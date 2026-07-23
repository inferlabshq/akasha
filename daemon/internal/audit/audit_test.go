package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte("\n"))
}

// Emit blocks rather than dropping, so every event survives even when far more
// are emitted than the in-memory buffer holds (finding #6).
func TestNoDropUnderLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("AKASHA_AUDIT_MAX_SIZE", "1073741824") // 1 GiB → one segment, isolate no-drop
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	const n = 5000 // well beyond the 4096 buffer, so Emit must block, not drop
	for i := 0; i < n; i++ {
		l.Emit(Event{Action: ActionRetrieved, AgentID: "a", Token: fmt.Sprintf("t%d", i)})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if got := countLines(t, path); got != n {
		t.Fatalf("recorded %d events, want %d — events were dropped", got, n)
	}
}

// Rotation caps a segment's size and retention caps how many are kept, so the
// on-disk log stays bounded instead of growing until the disk fills.
func TestRotationAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("AKASHA_AUDIT_MAX_SIZE", "400") // tiny → rotate every few events
	t.Setenv("AKASHA_AUDIT_KEEP", "2")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		l.Emit(Event{Action: ActionRetrieved, AgentID: "a", Token: fmt.Sprintf("token-%d", i)})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// The active segment must still exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active audit.log missing: %v", err)
	}
	// Rotation must have happened, and retention must cap the rotated segments.
	segs, _ := filepath.Glob(path + ".*")
	if len(segs) == 0 {
		t.Fatal("expected rotation to have occurred")
	}
	if len(segs) > 2 {
		t.Fatalf("retention not enforced: %d rotated segments, want <= 2", len(segs))
	}
}
