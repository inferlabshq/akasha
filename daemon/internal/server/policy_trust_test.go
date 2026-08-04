package server_test

import (
	"net/http"
	"strings"
	"testing"
)

// These cover the trust boundary between what the DAEMON knows and what a
// CALLER claims. Every test here corresponds to a bypass that was live in a
// shipped build, so each one is a regression guard, not a feature test.

// TestAssertedToolCannotSatisfyAllow is the headline regression.
//
// The shipped starter policy expressed "the credential broker may use secrets"
// as `action: retrieve` + `tool: akasha_helper` -> allow, sitting above a
// blanket `action: retrieve` -> deny. But `requesting_tool` is a free-text
// request-body field, so writing that one string satisfied the allow rule and
// returned raw plaintext. It was reachable from a prompt-injected agent without
// a shell, since `requesting_tool` is an ordinary argument of the vault_retrieve
// MCP tool.
//
// The policy below is the OLD starter policy verbatim. Even against it, the
// claim must not work.
func TestAssertedToolCannotSatisfyAllow(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - action: retrieve
    tool: akasha_helper
    effect: allow
    reason: brokered per-operation credential use
  - action: retrieve
    effect: deny
    reason: raw secret decryption is disabled
`)
	token := storeSSN(t, ts)

	// The control: an honest tool name is denied by rule 2.
	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "claude", "requesting_tool": "vault_retrieve",
	}, ""); code != 403 {
		t.Fatalf("honest tool name: got %d, want 403 (the deny rule should apply)", code)
	}

	// The bypass: claiming the broker's identity must NOT reach the vault.
	code, out := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "claude", "requesting_tool": "akasha_helper",
	}, "")
	if code == 200 {
		t.Fatalf("BYPASS: claiming requesting_tool=akasha_helper returned the secret (%v)", out["value"])
	}
	if code != 400 {
		t.Fatalf("claimed broker identity: got %d, want 400 (reserved namespace refused)", code)
	}
	if v, _ := out["value"].(string); v != "" {
		t.Fatalf("BYPASS: a non-200 response still carried a value %q", v)
	}
}

// TestReservedToolNamespaceRejected: no caller may claim any akasha_* tool
// identity, not just the one the old starter policy happened to name. The
// daemon assigns these to itself when it knows which internal path is running;
// a body field must never collide with one.
func TestReservedToolNamespaceRejected(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, "rules: []\n")
	token := storeSSN(t, ts)

	for _, tool := range []string{
		"akasha_helper",
		"akasha_assume",
		"akasha_list",
		"AKASHA_HELPER",   // case must not be an escape
		"  akasha_helper", // nor leading whitespace
		"akasha_anything_at_all",
	} {
		code, _ := post(t, ts, "/retrieve", map[string]string{
			"token": token, "agent_id": "a", "requesting_tool": tool,
		}, "")
		if code != 400 {
			t.Errorf("requesting_tool=%q: got %d, want 400", tool, code)
		}
	}

	// A normal tool name still works — this guard must not break real callers.
	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "a", "requesting_tool": "my_tool",
	}, ""); code != 200 {
		t.Errorf("ordinary tool name: got %d, want 200", code)
	}
}

// TestReservedToolNamespaceRejectedOnGrant: /grant takes a caller-supplied
// allowed_tool that is likewise matched by policy, so it needs the same guard.
func TestReservedToolNamespaceRejectedOnGrant(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, "rules: []\n")
	token := storeSSN(t, ts)

	if code, _ := post(t, ts, "/grant", map[string]interface{}{
		"token": token, "grantor_agent": "a", "grantee_agent": "b",
		"allowed_tool": "akasha_helper", "ttl_seconds": 60,
	}, ""); code != 400 {
		t.Errorf("allowed_tool=akasha_helper: got %d, want 400", code)
	}

	if code, out := post(t, ts, "/grant", map[string]interface{}{
		"token": token, "grantor_agent": "a", "grantee_agent": "b",
		"allowed_tool": "read_pr", "ttl_seconds": 60,
	}, ""); code != 200 || out["grant_id"] == nil {
		t.Errorf("ordinary allowed_tool: got %d (grant_id=%v), want 200 with an id", code, out["grant_id"])
	}
}

// TestAliasLaunderingBlocked is the second confirmed bypass.
//
// `labels.token` is not unique, so a caller could bind a second name to an
// already-vaulted secret and then request it under the new name. Policy matched
// on the name the CALLER chose, so every provider:/instance: rule was walked
// past:
//
//	POST /label/set {"name":"zz:1","token":"<token behind aws:prod>"}
//	GET  /label/get?name=zz:1        → policy saw provider "zz", not "aws"
//
// Reads are now evaluated against every name the token answers to.
func TestAliasLaunderingBlocked(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: assume
    provider: aws
    instance: prod
    effect: deny
    reason: production AWS is off limits
`)
	tok := storeSSN(t, ts)
	if err := vlt.SetLabel("aws:prod", tok); err != nil {
		t.Fatal(err)
	}

	// Control: the original name is denied.
	if resp, _ := ts.Client().Get(ts.URL + "/label/get?name=aws:prod"); resp.StatusCode != 403 {
		t.Fatalf("aws:prod direct: got %d, want 403", resp.StatusCode)
	}

	// Mint the alias. Binding is a separate action, so the assume-deny above
	// does not block it — the read is where laundering has to be caught.
	if code, _ := post(t, ts, "/label/set", map[string]string{
		"name": "zz:1", "token": tok,
	}, ""); code != 200 {
		t.Fatalf("bind alias: got %d, want 200", code)
	}

	// The bypass: reading through the alias must still be denied.
	resp, err := ts.Client().Get(ts.URL + "/label/get?name=zz:1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 200 {
		t.Fatal("BYPASS: alias zz:1 returned a secret that aws:prod is denied")
	}
	if resp.StatusCode != 403 {
		t.Fatalf("alias read: got %d, want 403", resp.StatusCode)
	}
}

// TestAliasDoesNotBlockUnrelatedSecrets: the union rule must restrict aliases
// of a denied secret without becoming a blanket denial.
func TestAliasDoesNotBlockUnrelatedSecrets(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: assume
    provider: aws
    instance: prod
    effect: deny
    reason: production AWS is off limits
`)
	other := storeSSN(t, ts)
	if err := vlt.SetLabel("github:default", other); err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Get(ts.URL + "/label/get?name=github:default")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unrelated label: got %d, want 200 (the alias rule must not over-deny)", resp.StatusCode)
	}
}

// TestWriteSideIsGated: /label/set, /put, /profile/save and /vault/purge were
// all reachable with no policy check at all. /put in particular could re-point
// an existing label at attacker-supplied credentials, so the human's next
// credential-helper call would authenticate as the attacker.
func TestWriteSideIsGated(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: deny
rules: []
`)
	tok, err := vlt.Store("x", "Credential", "high", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}

	if code, _ := post(t, ts, "/label/set", map[string]string{"name": "a:b", "token": tok}, ""); code != 403 {
		t.Errorf("/label/set: got %d, want 403", code)
	}
	if code, _ := post(t, ts, "/put", map[string]interface{}{
		"label": "aws:default", "fields": map[string]string{"k": "v"},
	}, ""); code != 403 {
		t.Errorf("/put: got %d, want 403", code)
	}
	if code, _ := post(t, ts, "/profile/save", map[string]interface{}{
		"provider": "aws", "profile": "default", "token": tok,
	}, ""); code != 403 {
		t.Errorf("/profile/save: got %d, want 403", code)
	}
	if code, _ := post(t, ts, "/vault/purge", map[string]string{}, ""); code != 403 {
		t.Errorf("/vault/purge: got %d, want 403", code)
	}
}

// TestRebindEvaluatesAsCritical: creating a new label is routine, but
// re-pointing an existing one silently changes which credential the user's
// tooling authenticates with. Only the latter should trip a min_risk:critical
// bind rule.
func TestRebindEvaluatesAsCritical(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: bind
    min_risk: critical
    effect: deny
    reason: re-pointing an existing label needs review
`)
	first, err := vlt.Store("one", "Credential", "high", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := vlt.Store("two", "Credential", "high", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}

	// New label → "high" → the critical rule does not match → allowed.
	if code, _ := post(t, ts, "/label/set", map[string]string{
		"name": "aws:default", "token": first,
	}, ""); code != 200 {
		t.Fatalf("new bind: got %d, want 200", code)
	}

	// Re-point the same name at a different secret → "critical" → denied.
	if code, _ := post(t, ts, "/label/set", map[string]string{
		"name": "aws:default", "token": second,
	}, ""); code != 403 {
		t.Fatalf("rebind: got %d, want 403", code)
	}

	// Re-writing the SAME binding is idempotent, not a redirect.
	if code, _ := post(t, ts, "/label/set", map[string]string{
		"name": "aws:default", "token": first,
	}, ""); code != 200 {
		t.Fatalf("idempotent re-bind: got %d, want 200", code)
	}
}

// TestMethodAllowList: no handler validated the HTTP method, so a browser
// subresource load reached state-changing endpoints — an <img> GET carries a
// loopback Host and no Origin, which hostGuard permits by design.
func TestMethodAllowList(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, "rules: []\n")

	resp, err := ts.Client().Get(ts.URL + "/vault/purge")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /vault/purge: got %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("Allow header = %q, want it to advertise POST", allow)
	}

	req, _ := http.NewRequest("POST", ts.URL+"/label/get?name=a:b", nil)
	r2, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /label/get: got %d, want 405", r2.StatusCode)
	}
}
