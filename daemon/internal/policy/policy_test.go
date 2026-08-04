package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePolicy(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// No policy file: everything is allowed (pre-policy behaviour preserved).
func TestMissingFileAllowsAll(t *testing.T) {
	e := NewEngine(filepath.Join(t.TempDir(), "nope.yaml"))
	if err := e.Authorize(Request{Action: "retrieve", AgentID: "claude", Risk: "critical"}); err != nil {
		t.Fatalf("missing policy file must allow: %v", err)
	}
}

// A file that exists but does not parse denies everything, loudly.
func TestBrokenFileDeniesAll(t *testing.T) {
	path := writePolicy(t, t.TempDir(), "rules: [{effect: maybe}]")
	e := NewEngine(path)
	err := e.Authorize(Request{Action: "retrieve"})
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("broken policy must deny all, got %v", err)
	}
}

func TestFirstMatchWins(t *testing.T) {
	path := writePolicy(t, t.TempDir(), `
version: 1
rules:
  - action: retrieve
    agent: claude
    effect: allow
  - action: retrieve
    effect: deny
    reason: everyone else
`)
	e := NewEngine(path)
	// AgentSource must be stated: an agent: matcher can only satisfy an allow
	// when the identity is key-verified or assigned by the daemon.
	if err := e.Authorize(Request{Action: "retrieve", AgentID: "claude", AgentSource: Verified}); err != nil {
		t.Fatalf("claude should match rule 1 (allow): %v", err)
	}
	err := e.Authorize(Request{Action: "retrieve", AgentID: "cursor", AgentSource: Verified})
	if err == nil || !strings.Contains(err.Error(), "everyone else") {
		t.Fatalf("cursor should hit rule 2 (deny): %v", err)
	}
}

func TestGlobAndCaseInsensitive(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - agent: "vscode*"
    provider: AWS
    effect: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{AgentID: "vscode-insiders", Provider: "aws"})
	if d.Effect != EffectDeny {
		t.Fatalf("glob + case-insensitive match failed: %+v", d)
	}
	d = p.Evaluate(Request{AgentID: "claude", Provider: "aws"})
	if d.Effect != EffectAllow {
		t.Fatalf("non-matching agent should fall through to default allow: %+v", d)
	}
}

func TestMinRiskThreshold(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - min_risk: high
    effect: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	for risk, want := range map[string]Effect{
		"low": EffectAllow, "medium": EffectAllow,
		"high": EffectDeny, "critical": EffectDeny,
		"": EffectAllow, // unclassified doesn't reach the threshold
	} {
		if d := p.Evaluate(Request{Risk: risk}); d.Effect != want {
			t.Fatalf("risk %q: want %s got %s", risk, want, d.Effect)
		}
	}
}

func TestDefaultDeny(t *testing.T) {
	p, err := Parse([]byte(`
default: deny
rules:
  - agent: claude
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Request{AgentID: "claude", AgentSource: Verified}); d.Effect != EffectAllow {
		t.Fatal("explicit allow rule should win over default deny")
	}
	if d := p.Evaluate(Request{AgentID: "unknown", AgentSource: Verified}); d.Effect != EffectDeny {
		t.Fatal("unmatched request should get default deny")
	}
	// The same name, self-reported rather than key-backed, must NOT open the
	// lockdown: this is the whole point of the provenance split.
	if d := p.Evaluate(Request{AgentID: "claude", AgentSource: Asserted}); d.Effect != EffectDeny {
		t.Fatal("an asserted agent id must not satisfy an allow rule under default: deny")
	}
}

func TestParseRejectsUnknownFieldsAndBadValues(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field": "rules: [{effect: allow, agnet: claude}]",
		"bad effect":    "rules: [{effect: block}]",
		"bad risk":      "rules: [{effect: deny, min_risk: severe}]",
		"bad action":    "rules: [{effect: deny, action: read}]",
		"bad default":   "default: ask",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("%s: expected parse error for %q", name, doc)
		}
	}
}

type fakeApprover struct {
	allow  bool
	called int
	last   Request
}

func (f *fakeApprover) Approve(req Request, _ time.Duration) bool {
	f.called++
	f.last = req
	return f.allow
}

func TestAskResolvesThroughApprover(t *testing.T) {
	path := writePolicy(t, t.TempDir(), `
rules:
  - min_risk: critical
    effect: ask
    reason: critical data
`)
	e := NewEngine(path)

	fa := &fakeApprover{allow: true}
	e.SetApprover(fa)
	req := Request{Action: "retrieve", AgentID: "claude", Risk: "critical", Category: "SSN"}
	if err := e.Authorize(req); err != nil {
		t.Fatalf("approved ask should allow: %v", err)
	}
	if fa.called != 1 || fa.last.Category != "SSN" {
		t.Fatalf("approver not consulted with request context: %+v", fa)
	}

	fa.allow = false
	if err := e.Authorize(req); err == nil {
		t.Fatal("rejected ask must deny")
	}

	// No approver available: ask fails closed.
	e.SetApprover(nil)
	if err := e.Authorize(req); err == nil {
		t.Fatal("ask with no approver must deny")
	}
}

// Editing the file takes effect without restarting the engine.
func TestReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, "rules: [{agent: claude, effect: deny}]")
	e := NewEngine(path)

	if err := e.Authorize(Request{AgentID: "claude"}); err == nil {
		t.Fatal("expected deny from initial policy")
	}

	// Rewrite with different content (size change guarantees detection even
	// on filesystems with coarse mtime granularity).
	if err := os.WriteFile(path, []byte("rules: [{agent: nobody-here, effect: deny}]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Authorize(Request{AgentID: "claude"}); err != nil {
		t.Fatalf("edited policy should now allow claude: %v", err)
	}
}

func TestAppleScriptQuote(t *testing.T) {
	got := appleScriptQuote("say \"hi\"\nback\\slash")
	want := `"say \"hi\"\nback\\slash"`
	if got != want {
		t.Fatalf("want %s got %s", want, got)
	}
}
