package classifier_test

import (
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/classifier"
)

func TestParseConfigBasic(t *testing.T) {
	cfg := `
# custom patterns
- name: Acme Employee ID
  category: EmployeeID
  risk: high
  pattern: EMP-\d{6}

- name: Internal Ticket
  category: TicketRef
  risk: low
  pattern: ACME-[A-Z]+-\d+
`
	pats, err := classifier.ParseConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(pats) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(pats))
	}
	if pats[0].Name != "Acme Employee ID" || pats[0].Category != "EmployeeID" || pats[0].Risk != "high" {
		t.Fatalf("pattern 0 wrong: %+v", pats[0])
	}

	// Verify the compiled regex works end-to-end via the classifier.
	clf := classifier.New(pats)
	r := clf.Classify("lookup", "employee EMP-123456 requested access")
	if !r.Sensitive || r.Category != "EmployeeID" {
		t.Fatalf("custom pattern not matched: %+v", r)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	pats, err := classifier.ParseConfig("- name: X\n  pattern: foo")
	if err != nil {
		t.Fatal(err)
	}
	if pats[0].Risk != "medium" || pats[0].Category != "Custom" {
		t.Fatalf("defaults not applied: %+v", pats[0])
	}
}

func TestParseConfigInvalidRegex(t *testing.T) {
	_, err := classifier.ParseConfig("- name: bad\n  pattern: (unclosed")
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestParseConfigMissingPattern(t *testing.T) {
	_, err := classifier.ParseConfig("- name: nopattern\n  risk: high")
	if err == nil {
		t.Fatal("expected error for block missing pattern")
	}
}

func TestParseConfigEmpty(t *testing.T) {
	pats, err := classifier.ParseConfig("# just a comment\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(pats) != 0 {
		t.Fatalf("expected 0 patterns, got %d", len(pats))
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	// Missing file must return nil, nil — not an error.
	pats, err := classifier.LoadConfig("/nonexistent/path/patterns.yaml")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if pats != nil {
		t.Fatal("expected nil patterns for missing file")
	}
}
