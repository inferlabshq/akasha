package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func firstBreak(t *testing.T, path string) Break {
	t.Helper()
	r, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Breaks) == 0 {
		t.Fatal("expected a break, the chain verified clean")
	}
	return r.Breaks[0]
}

// Editing a line -- valid JSON, one field changed -- is caught at the NEXT
// line, whose prev no longer matches, and the report names the edited line as
// the suspect. This is the whole point: a same-uid attacker who rewrites one
// record without recomputing every successor leaves the break behind.
func TestAnEditedLineIsDetectedAtItsSuccessor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	emitN(t, path, 50)
	ls := lines(t, path)
	ls[19] = bytes.Replace(ls[19], []byte(`"line 20"`), []byte(`"line 2O"`), 1) // still valid JSON
	if err := os.WriteFile(path, append(bytes.Join(ls, []byte("\n")), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	b := firstBreak(t, path)
	if b.Kind != "modified" || b.Line != 21 {
		t.Errorf("want modified at line 21, got %+v", b)
	}
	r, _ := Verify(path)
	if !r.Tampered() {
		t.Error("an edit must count as tampering")
	}
}

// Deleting a line is caught the same way: the line that followed it now
// chains to a hash nothing on disk has.
func TestADeletedLineIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	emitN(t, path, 50)
	ls := lines(t, path)
	ls = append(ls[:19], ls[20:]...)
	if err := os.WriteFile(path, append(bytes.Join(ls, []byte("\n")), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	b := firstBreak(t, path)
	if b.Kind != "modified" || b.Line != 20 {
		t.Errorf("want modified at line 20 (the successor of the deleted one), got %+v", b)
	}
}

// Truncating the END of a rotated segment is caught at the first line of the
// next segment, which chains to a line that is no longer there.
func TestATruncatedSegmentTailIsDetectedAtTheNextSegment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("AKASHA_AUDIT_MAX_SIZE", "600")
	t.Setenv("AKASHA_AUDIT_KEEP", "50")
	emitN(t, path, 40)
	segs, _ := filepath.Glob(path + ".*")
	if len(segs) < 2 {
		t.Fatalf("need at least two rotated segments, got %d", len(segs))
	}
	// sort by name = by age; drop the last line of the oldest segment
	oldest := segs[0]
	for _, s := range segs {
		if s < oldest {
			oldest = s
		}
	}
	ls := lines(t, oldest)
	if err := os.WriteFile(oldest, append(bytes.Join(ls[:len(ls)-1], []byte("\n")), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	b := firstBreak(t, path)
	if b.Kind != "modified" || b.Line != 1 {
		t.Errorf("want modified at line 1 of the following segment, got %+v", b)
	}
}
