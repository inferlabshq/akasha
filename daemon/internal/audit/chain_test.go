package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// emitN writes n chained events through a fresh Logger and closes it.
func emitN(t *testing.T, path string, n int) {
	t.Helper()
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		l.Emit(Event{Action: ActionInspected, AgentID: "a", Task: fmt.Sprintf("line %d", i)})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func lines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, l := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

func verifyClean(t *testing.T, path string) Report {
	t.Helper()
	r, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Breaks) != 0 {
		t.Fatalf("expected an intact chain, got breaks: %+v", r.Breaks)
	}
	return r
}

// Fifty events, one writer: every line chains to the one before it, seq is
// dense, and the report's head is the hash of the last line.
func TestChainIsIntactAndDense(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	emitN(t, path, 50)
	r := verifyClean(t, path)
	if r.Lines != 50 || r.LastSeq != 50 || r.Legacy != 0 {
		t.Errorf("report = %+v", r)
	}
	ls := lines(t, path)
	if r.Head != hashBytes(ls[len(ls)-1]) {
		t.Error("head is not the hash of the last line")
	}
	var first struct {
		Seq  uint64 `json:"seq"`
		Prev string `json:"prev"`
	}
	json.Unmarshal(ls[0], &first)
	if first.Seq != 1 || first.Prev != genesisPrev {
		t.Errorf("first line: seq=%d prev=%s, want 1 and genesis", first.Seq, first.Prev)
	}
}

// A new Logger on an existing log continues the chain from the tail. This is
// every daemon restart; the chain must not restart with it.
func TestSecondWriterContinuesTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	emitN(t, path, 10)
	emitN(t, path, 10)
	r := verifyClean(t, path)
	if r.LastSeq != 20 {
		t.Errorf("LastSeq = %d, want 20 -- the second writer restarted the chain", r.LastSeq)
	}
}

// Rotation must carry the chain across the segment boundary: the first line of
// the new segment chains to the last line of the old one.
func TestRotationPreservesContinuity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("AKASHA_AUDIT_MAX_SIZE", "600") // a few lines per segment
	t.Setenv("AKASHA_AUDIT_KEEP", "50")
	emitN(t, path, 40)
	r := verifyClean(t, path)
	if r.Segments < 3 {
		t.Fatalf("expected several segments, got %d -- rotation did not happen, the test proves nothing", r.Segments)
	}
	if r.LastSeq != 40 {
		t.Errorf("LastSeq = %d across %d segments, want 40", r.LastSeq, r.Segments)
	}
}

// Two Loggers open on one file at once (restore --offline while the daemon is
// up) fork the chain. That is not tampering and must not be reported as it.
func TestConcurrentWritersAreReportedAsAForkNotAnEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	emitN(t, path, 3)
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Emit(Event{Action: ActionInspected, AgentID: "a", Task: "from a"})
	a.Close()
	b.Emit(Event{Action: ActionInspected, AgentID: "b", Task: "from b"})
	b.Close()
	r, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tampered() {
		// A fork is not tampering; Tampered() is the flag the CLI exits 1 on.
		var kinds []string
		for _, br := range r.Breaks {
			kinds = append(kinds, br.Kind)
		}
		if strings.Contains(strings.Join(kinds, ","), "modified") {
			t.Errorf("a concurrent writer was reported as an edit: %+v", r.Breaks)
		}
	}
	forks := 0
	for _, br := range r.Breaks {
		if br.Kind == "fork" {
			forks++
		}
	}
	if forks != 1 {
		t.Errorf("want exactly one fork break, got %+v", r.Breaks)
	}
}

// The active file shrinking behind a running daemon is the one tampering it
// can see happen. It records an AUDIT_GAP naming what it saw, reseeds from
// what is on disk, and keeps going; seq continues so the gap is visible
// offline too.
func TestLiveTruncationIsRecordedAsAGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		l.Emit(Event{Action: ActionInspected, AgentID: "a"})
	}
	l.flushForTest()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	l.Emit(Event{Action: ActionInspected, AgentID: "a", Task: "after truncation"})
	l.Close()

	ls := lines(t, path)
	if len(ls) != 2 {
		t.Fatalf("want AUDIT_GAP then the event, got %d line(s)", len(ls))
	}
	var gap map[string]interface{}
	json.Unmarshal(ls[0], &gap)
	if gap["action"] != string(ActionAuditGap) {
		t.Errorf("first line after truncation is %v, want AUDIT_GAP", gap["action"])
	}
	if !strings.Contains(fmt.Sprint(gap["task"]), "shrank") {
		t.Errorf("the gap record must say what happened: %v", gap["task"])
	}
	r, _ := Verify(path)
	hasGap := false
	for _, br := range r.Breaks {
		if br.Kind == "gap" {
			hasGap = true
		}
	}
	if !hasGap {
		t.Errorf("Verify did not report the gap: %+v", r)
	}
	if r.Tampered() {
		t.Errorf("a recorded gap is not an edit, but Tampered() is true: %+v", r.Breaks)
	}
}

// A torn tail (the daemon died mid-write) is left as it is, terminated, and
// reported as torn. It is never rewritten.
func TestTornTailIsTerminatedNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	emitN(t, path, 3)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"action":"INSPECTED","seq":4,"prev":"partial`)
	f.Close()
	before, _ := os.ReadFile(path)

	emitN(t, path, 1)
	after, _ := os.ReadFile(path)
	if !bytes.HasPrefix(after, before) {
		t.Fatal("the torn bytes were rewritten -- an audit log must only ever be appended to")
	}
	r, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	torn := 0
	for _, br := range r.Breaks {
		if br.Kind == "torn" {
			torn++
		} else if br.Kind == "modified" {
			t.Errorf("a torn line was reported as an edit: %+v", br)
		}
	}
	if torn != 1 {
		t.Errorf("want one torn break, got %+v", r.Breaks)
	}
}

// A log written before the chain existed is legacy; the first chained line
// commits to its last legacy line, and Verify reports the transition rather
// than a break.
func TestLegacyPrefixThenChained(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	legacy := `{"action":"INSPECTED","agent_id":"old","timestamp":"2026-01-01T00:00:00Z"}` + "\n" +
		`{"action":"VAULTED","agent_id":"old","timestamp":"2026-01-01T00:00:01Z"}` + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	emitN(t, path, 3)
	r := verifyClean(t, path)
	if r.Legacy != 2 || r.LastSeq != 3 {
		t.Errorf("report = %+v, want 2 legacy lines and LastSeq 3", r)
	}
	ls := lines(t, path)
	var first struct {
		Prev string `json:"prev"`
	}
	json.Unmarshal(ls[2], &first)
	if first.Prev != hashBytes(ls[1]) {
		t.Error("the first chained line does not commit to the last legacy line")
	}
}
