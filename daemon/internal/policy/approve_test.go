package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The approval dialog is the last line of defence, and its entire body used to
// be written by the thing being gated: appleScriptQuote turned "\n" into the
// AppleScript escape `\n`, which renders as a REAL line break, so a caller could
// forge lines that read exactly like the daemon's own labels.

func TestDialogRejectsControlCharacters(t *testing.T) {
	// The forgery: a task that closes the real block and opens a fake one.
	injected := "sync\nRisk: low\nTool: akasha_helper\nOperation: broker aws:dev"
	got := dialogSafe(injected, maxTaskLen)

	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("dialogSafe left a line break in %q", got)
	}
	// The text survives — we are neutralising layout, not censoring content.
	for _, word := range []string{"sync", "Risk:", "low"} {
		if !strings.Contains(got, word) {
			t.Errorf("dialogSafe dropped %q from the value: %q", word, got)
		}
	}

	// Carriage return renders as a line break too and was previously unhandled.
	if strings.ContainsAny(dialogSafe("a\rb", maxFieldLen), "\r") {
		t.Error("carriage return survived")
	}
	// Other C0 controls are dropped outright.
	if out := dialogSafe("a\x00\x07b", maxFieldLen); out != "ab" {
		t.Errorf("C0 controls: got %q, want %q", out, "ab")
	}
}

func TestDialogFieldsAreCapped(t *testing.T) {
	// An unbounded field could make the dialog taller than the screen and push
	// the Deny/Allow buttons out of view. Only Task used to be capped.
	long := strings.Repeat("A", 5000)
	if n := len([]rune(dialogSafe(long, maxFieldLen))); n > maxFieldLen+1 {
		t.Errorf("field capped to %d runes, got %d", maxFieldLen, n)
	}
	if n := len([]rune(dialogSafe(long, maxTaskLen))); n > maxTaskLen+1 {
		t.Errorf("task capped to %d runes, got %d", maxTaskLen, n)
	}
}

// truncate sliced BYTES, so a cut through a multi-byte character emitted
// invalid UTF-8 — which osascript rejects, turning a long description into a
// failed dialog, i.e. a silent deny.
func TestTruncateSlicesRunes(t *testing.T) {
	s := strings.Repeat("é", 300) // 2 bytes per rune
	got := truncate(s, 200)
	if !utf8Valid(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if n := len([]rune(got)); n != 201 { // 200 + the ellipsis
		t.Errorf("got %d runes, want 201", n)
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// countingApprover records the maximum number of approvals in flight at once.
type countingApprover struct {
	inFlight int32
	maxSeen  int32
	allow    bool
}

func (c *countingApprover) Approve(Request, time.Duration) bool {
	n := atomic.AddInt32(&c.inFlight, 1)
	for {
		max := atomic.LoadInt32(&c.maxSeen)
		if n <= max || atomic.CompareAndSwapInt32(&c.maxSeen, max, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond) // hold the "dialog" open
	atomic.AddInt32(&c.inFlight, -1)
	return c.allow
}

// TestApprovalsAreSerialized: the HTTP server runs a goroutine per request, so
// N concurrent gated operations used to open N modal dialogs at once — no cap,
// no dedupe, no cooldown. Flooding a user until they click Allow on one is a
// practical attack, especially when several dialogs look identical and only one
// is dangerous.
func TestApprovalsAreSerialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("rules:\n  - {effect: ask}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(path)
	app := &countingApprover{allow: true}
	e.SetApprover(app)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.Authorize(Request{Action: "retrieve"})
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&app.maxSeen); got != 1 {
		t.Fatalf("%d approvals ran concurrently, want 1 — dialogs must not stack", got)
	}
}

// Serialising must not change the outcome: a denied approval is still a denial.
func TestSerializedApprovalStillDenies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte("rules:\n  - {effect: ask}\n"), 0600)
	e := NewEngine(path)
	e.SetApprover(&countingApprover{allow: false})

	if err := e.Authorize(Request{Action: "retrieve"}); err == nil {
		t.Fatal("a refused approval must deny")
	}
}
