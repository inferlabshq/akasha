package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readEvents drains the log file into decoded events.
func readEvents(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]interface{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad log line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func newTestLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}

// TestAuditRedactsTokensEverywhere: not just the Token field. Task,
// ReasoningTrace and TriggeredBy are written by the agent, so redacting only
// the structured field would leave the agent a channel to log its own tokens.
func TestAuditRedactsTokensEverywhere(t *testing.T) {
	l, path := newTestLogger(t)
	const tok = "vault://oa2PMh8KYd0"
	const grant = "grt://AbCdEfGhIjKlMnOp"

	l.Emit(Event{
		Action:         ActionRetrieved,
		Token:          tok,
		GrantID:        grant,
		Task:           "read config from " + tok,
		ReasoningTrace: "needed " + grant + " for the handoff",
		TriggeredBy:    tok,
	})
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{tok, grant} {
		if strings.Contains(body, secret) {
			t.Errorf("log still contains %q:\n%s", secret, body)
		}
	}
	// The bare scheme prefix must not survive either — that is what makes a
	// token greppable in the first place.
	if strings.Contains(body, "vault://") || strings.Contains(body, "grt://") {
		t.Errorf("log still contains a raw token prefix:\n%s", body)
	}

	ev := readEvents(t, path)[0]
	if got, _ := ev["token"].(string); !strings.HasPrefix(got, "tk_") {
		t.Errorf("token = %q, want a tk_ digest", got)
	}
	if got, _ := ev["task"].(string); !strings.Contains(got, "tk_") {
		t.Errorf("task = %q, want the embedded token digested in place", got)
	}
	// Surrounding prose is preserved — only the identifier is replaced.
	if got, _ := ev["task"].(string); !strings.HasPrefix(got, "read config from ") {
		t.Errorf("task = %q, want the prose intact", got)
	}
}

// TestAuditDigestIsStableAcrossEvents: correlation is the entire reason the
// token is in the log, so the same secret must produce the same digest in every
// event — and two different secrets must not collide.
func TestAuditDigestIsStableAcrossEvents(t *testing.T) {
	l, path := newTestLogger(t)
	const a = "vault://AAAAAAAAAAA"
	const b = "vault://BBBBBBBBBBB"

	l.Emit(Event{Action: ActionVaulted, Token: a})
	l.Emit(Event{Action: ActionRetrieved, Token: a})
	l.Emit(Event{Action: ActionRetrieved, Token: b})
	l.Close()

	ev := readEvents(t, path)
	if len(ev) != 3 {
		t.Fatalf("got %d events, want 3", len(ev))
	}
	d0, _ := ev[0]["token"].(string)
	d1, _ := ev[1]["token"].(string)
	d2, _ := ev[2]["token"].(string)
	if d0 != d1 {
		t.Errorf("same secret produced different digests: %q vs %q", d0, d1)
	}
	if d0 == d2 {
		t.Error("different secrets produced the same digest")
	}
}

// An empty token must stay empty, or omitempty stops eliding it and every
// event grows a meaningless field.
func TestAuditEmptyTokenStaysEmpty(t *testing.T) {
	l, path := newTestLogger(t)
	l.Emit(Event{Action: ActionDenied, AgentID: "claude"})
	l.Close()

	ev := readEvents(t, path)[0]
	if _, present := ev["token"]; present {
		t.Errorf("empty token was materialised into the log: %v", ev)
	}
}

// The digest must not depend on process state — correlation has to hold across
// daemon restarts and vault rebuilds, which is why it is unkeyed.
func TestRedactTokenIsDeterministic(t *testing.T) {
	const tok = "vault://oa2PMh8KYd0"
	if redactToken(tok) != redactToken(tok) {
		t.Fatal("digest is not deterministic")
	}
	if redactToken("") != "" {
		t.Fatal("empty input must stay empty")
	}
	if strings.Contains(redactToken(tok), tok) {
		t.Fatal("digest contains its input")
	}
}
