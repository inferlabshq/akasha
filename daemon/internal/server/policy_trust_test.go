package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestBodyAgentIDCannotSatisfyAllow: /retrieve reads agent_id from the request
// body, so a lockdown policy that grants by agent name must not be openable by
// simply typing that name.
func TestBodyAgentIDCannotSatisfyAllow(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
default: deny
rules:
  - action: retrieve
    agent: claude
    effect: allow
    reason: claude may read
`)
	token := storeSSN(t, ts)

	if code, out := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "claude", "requesting_tool": "vault_retrieve",
	}, ""); code == 200 {
		t.Fatalf("BYPASS: self-reported agent_id opened the lockdown (%v)", out["value"])
	} else if code != 403 {
		t.Fatalf("asserted agent_id: got %d, want 403", code)
	}
}

// TestVerifiedAgentIDSatisfiesAllow: the same rule must still work for a caller
// that actually holds the key — otherwise the lockdown posture is unusable.
func TestVerifiedAgentIDSatisfiesAllow(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: deny
rules:
  - action: retrieve
    agent: claude
    effect: allow
    reason: claude may read
`)
	token := storeSSN(t, ts)
	_, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": token, "requesting_tool": "vault_retrieve",
	}, key); code != 200 {
		t.Fatalf("key-verified claude: got %d, want 200", code)
	}
}

// TestServerAssignedIdentityStillGrants is the non-regression guard at the HTTP
// layer: /label/list names its own caller (akasha-list) and ignores the body, so
// a rule written against that name is not forgeable and must keep granting.
// A blanket "keyless is untrusted" rule would have broken this.
func TestServerAssignedIdentityStillGrants(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
default: deny
rules:
  - action: list
    agent: akasha-list
    effect: allow
    reason: the inventory command may run
`)
	resp, err := ts.Client().Get(ts.URL + "/label/list")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("server-assigned akasha-list: got %d, want 200", resp.StatusCode)
	}
}

// TestStoreRejectsInvalidRisk closes the second live bypass.
//
// `risk` was a free-text body field on an ungated endpoint, and the policy
// engine ranked an unrecognised level as 0 — below every threshold. So an agent
// could vault its own loot one typo away from a real level and make it
// permanently invisible to every min_risk rule:
//
//	POST /store {"content":"...","risk":"criticall"}   → stored, unrankable
//	POST /retrieve {"token":...}                        → no min_risk rule matched
func TestStoreRejectsInvalidRisk(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - action: retrieve
    min_risk: low
    effect: deny
    reason: nothing classified may be read raw
`)

	for _, bad := range []string{"criticall", "none", "HIGHEST", "0"} {
		code, _ := post(t, ts, "/store", map[string]string{
			"agent_id": "a", "tool_name": "t", "content": "429-21-0001",
			"category": "SSN", "risk": bad,
		}, "")
		if code != 400 {
			t.Errorf("/store risk=%q: got %d, want 400", bad, code)
		}
	}

	// A real level still works, and is then actually covered by the rule.
	code, out := post(t, ts, "/store", map[string]string{
		"agent_id": "a", "tool_name": "t", "content": "429-21-0002",
		"category": "SSN", "risk": "critical",
	}, "")
	if code != 200 {
		t.Fatalf("/store risk=critical: got %d, want 200", code)
	}
	tok, _ := out["token"].(string)
	if c, _ := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "a", "requesting_tool": "t",
	}, ""); c != 403 {
		t.Fatalf("retrieve of a critical entry: got %d, want 403", c)
	}
}

// Even if an unrankable entry exists (stored before this guard landed), the
// engine must not let it slip past a restrictive rule.
func TestLegacyUnrankableEntryStillGated(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: retrieve
    min_risk: low
    effect: deny
    reason: nothing classified may be read raw
`)
	// Bypass the handler to simulate a row written by an older build.
	tok, err := vlt.Store("429-21-0003", "SSN", "criticall", "legacy", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "a", "requesting_tool": "t",
	}, ""); code != 403 {
		t.Fatalf("legacy unrankable entry: got %d, want 403", code)
	}
}

// TestInspectDeniesBeforeDisclosingExistence: the gate must run before the 404,
// or a denied caller can distinguish a real token from an invented one.
func TestInspectDeniesBeforeDisclosingExistence(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, "default: deny\nrules: []\n")
	resp, err := ts.Client().Get(ts.URL + "/inspect?token=vault://definitely-not-real")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("inspect of an unknown token under default:deny: got %d, want 403", resp.StatusCode)
	}
}

// readAudit returns the events the test server wrote.
//
// Emit hands off to a drain goroutine, so a read immediately after a request
// can race the write. Poll until at least `want` events are visible rather than
// sleeping a fixed amount.
// waitForAudit polls the audit log until an event with the given action shows
// up, and returns every event read so far.
//
// It waits for the EVENT rather than for a count. Counting was fragile in a way
// that bit: `readAudit(t, dir, 2)` settled as soon as two lines existed, and
// once policy load/change events were added the first two became POLICY_LOADED
// and VAULTED — so the helper stopped looking before the DENIED it was actually
// waiting for. It passed locally and failed under -race, the signature of a
// test that is timing-dependent rather than wrong. Naming the event means a new
// event type cannot silently change what a test waits for.
func waitForAudit(t *testing.T, dir, action string, n int) []map[string]interface{} {
	t.Helper()
	var last []map[string]interface{}
	for i := 0; i < 200; i++ {
		last = readAuditNow(t, dir)
		got := 0
		for _, e := range last {
			if e["action"] == action {
				got++
			}
		}
		if got >= n {
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit log never recorded %d %s event(s) (saw %d events total)", n, action, len(last))
	return nil
}

// readAuditNow reads whatever is in the log now, tolerating a partially
// flushed final line.
func readAuditNow(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return out // drain goroutine is mid-write; caller retries
		}
		out = append(out, m)
	}
	return out
}

func readAudit(t *testing.T, dir string, want int) []map[string]interface{} {
	t.Helper()
	path := filepath.Join(dir, "audit.log")
	var out []map[string]interface{}
	for i := 0; i < 100; i++ {
		out = out[:0]
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				// A partially flushed final line — retry.
				out = nil
				break
			}
			out = append(out, m)
		}
		if len(out) >= want {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit log never reached %d events (got %d)", want, len(out))
	return nil
}

// TestAuditRecordsIdentitySource: a key-authenticated action and an anonymous
// one that merely typed the same agent_id produced identical log lines, so an
// attacker could attribute their own actions to someone else without stealing
// anything.
func TestAuditRecordsIdentitySource(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, "rules: []\n")
	tok := storeSSN(t, ts)
	_, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	// Anonymous caller claiming to be claude.
	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "claude", "requesting_tool": "t",
	}, ""); code != 200 {
		t.Fatalf("asserted retrieve: got %d", code)
	}
	// The real claude.
	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "requesting_tool": "t",
	}, key); code != 200 {
		t.Fatalf("verified retrieve: got %d", code)
	}

	var sources []string
	// TWO retrievals, so wait for both: the drain goroutine is asynchronous, and
	// stopping at the first left the second unwritten under -race.
	for _, e := range waitForAudit(t, dir, "RETRIEVED", 2) {
		if e["action"] == "RETRIEVED" {
			s, _ := e["identity_source"].(string)
			sources = append(sources, s)
		}
	}
	if len(sources) != 2 {
		t.Fatalf("want 2 RETRIEVED events, got %d (%v)", len(sources), sources)
	}
	if sources[0] != "asserted" {
		t.Errorf("self-reported identity logged as %q, want asserted", sources[0])
	}
	if sources[1] != "verified" {
		t.Errorf("key-backed identity logged as %q, want verified", sources[1])
	}
}

// /label/get hardcoded AgentID "akasha-assume", so the most sensitive
// disclosure in the daemon was attributed to a system pseudo-identity and a
// keyed agent's read looked exactly like the CLI's.
func TestLabelGetAuditUsesResolvedAgent(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, "rules: []\n")
	tok := storeSSN(t, ts)
	if err := vlt.SetLabel("aws:dev", tok); err != nil {
		t.Fatal(err)
	}
	_, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/label/get?name=aws:dev", nil)
	req.Header.Set("X-Akasha-Key", key)
	if _, err := ts.Client().Do(req); err != nil {
		t.Fatal(err)
	}

	for _, e := range waitForAudit(t, dir, "RETRIEVED", 1) {
		if e["action"] == "RETRIEVED" && strings.Contains(fmt.Sprint(e["task"]), "aws:dev") {
			if e["agent_id"] != "claude" {
				t.Fatalf("label/get attributed to %v, want claude", e["agent_id"])
			}
			if e["identity_source"] != "verified" {
				t.Fatalf("identity_source = %v, want verified", e["identity_source"])
			}
			return
		}
	}
	t.Fatal("no RETRIEVED event for the label read")
}

// A denial used to REPLACE the caller's task with the reason, dropping the
// stated purpose from the one record where it matters most.
func TestDenialKeepsCallerTask(t *testing.T) {
	ts, _, dir := newPolicyTestServerDir(t, `
rules:
  - {action: retrieve, effect: deny, reason: raw reads are off}
`)
	tok := storeSSN(t, ts)
	post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "a", "requesting_tool": "t",
		"task": "exfiltrating your database password",
	}, "")

	for _, e := range waitForAudit(t, dir, "DENIED", 1) {
		if e["action"] != "DENIED" {
			continue
		}
		task := fmt.Sprint(e["task"])
		if !strings.Contains(task, "raw reads are off") {
			t.Errorf("denial reason missing from %q", task)
		}
		if !strings.Contains(task, "exfiltrating your database password") {
			t.Errorf("caller's stated task missing from %q", task)
		}
		return
	}
	t.Fatal("no DENIED event")
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
