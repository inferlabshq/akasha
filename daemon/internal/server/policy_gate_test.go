package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

type stubApprover struct {
	allow  bool
	called int
}

func (a *stubApprover) Approve(policy.Request, time.Duration) bool {
	a.called++
	return a.allow
}

// newPolicyTestServer is newTestServer plus a policy file and a stub approver.
func newPolicyTestServer(t *testing.T, policyYAML string) (*httptest.Server, *vault.Vault, *stubApprover) {
	t.Helper()
	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(polPath, []byte(policyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(polPath)
	app := &stubApprover{}
	eng.SetApprover(app)

	srv := server.New(classifier.New(nil), vlt, auditL)
	srv.SetPolicyEngine(eng)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); auditL.Close(); vlt.Close() })
	return ts, vlt, app
}

// storeSSN vaults a critical entry and returns its token.
func storeSSN(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	code, out := post(t, ts, "/store", map[string]string{
		"agent_id": "seeder", "tool_name": "seed", "content": "429-21-0001",
		"category": "SSN", "risk": "critical",
	}, "")
	if code != 200 {
		t.Fatalf("store: status %d", code)
	}
	return out["token"].(string)
}

func TestPolicyDeniesRetrieveByRisk(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - action: retrieve
    min_risk: critical
    effect: deny
    reason: no critical retrievals
`)
	token := storeSSN(t, ts)
	code, body := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "claude", "requesting_tool": "lookup",
	}, "")
	if code != 403 {
		t.Fatalf("expected 403, got %d (%v)", code, body)
	}

	// A low-risk entry is untouched by the rule.
	_, st := post(t, ts, "/store", map[string]string{
		"agent_id": "seeder", "tool_name": "seed", "content": "someone@example.com",
		"category": "Email", "risk": "medium",
	}, "")
	code, out := post(t, ts, "/retrieve", map[string]string{
		"token": st["token"].(string), "agent_id": "claude", "requesting_tool": "lookup",
	}, "")
	if code != 200 || out["value"] != "someone@example.com" {
		t.Fatalf("medium-risk retrieve should pass: %d %v", code, out)
	}
}

func TestPolicyAskConsultsApprover(t *testing.T) {
	ts, _, app := newPolicyTestServer(t, `
rules:
  - action: retrieve
    min_risk: critical
    effect: ask
`)
	token := storeSSN(t, ts)
	req := map[string]string{"token": token, "agent_id": "claude", "requesting_tool": "lookup"}

	app.allow = true
	code, out := post(t, ts, "/retrieve", req, "")
	if code != 200 || out["value"] != "429-21-0001" {
		t.Fatalf("approved ask should retrieve: %d %v", code, out)
	}
	if app.called != 1 {
		t.Fatalf("approver should have been consulted once, got %d", app.called)
	}

	app.allow = false
	if code, _ := post(t, ts, "/retrieve", req, ""); code != 403 {
		t.Fatalf("rejected ask should 403, got %d", code)
	}
}

func TestPolicyDeniesAssumeByProviderAndAgent(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: assume
    provider: aws
    agent: intern-bot
    effect: deny
    reason: intern-bot may not assume aws
`)
	seedAWSCreds(t, vlt)

	code, body := post(t, ts, "/assume", map[string]interface{}{
		"provider": "aws", "profile": "default",
	}, agentKey(t, vlt, "intern-bot"))
	if code != 403 {
		t.Fatalf("expected 403 for intern-bot, got %d (%v)", code, body)
	}

	code, _ = post(t, ts, "/assume", map[string]interface{}{
		"provider": "aws", "profile": "default",
	}, agentKey(t, vlt, "prod-bot"))
	if code == 403 {
		t.Fatal("prod-bot should not be blocked by intern-bot's rule")
	}
}

// The metadata endpoints (inventory + per-token metadata) pass the policy gate,
// so a deny-all default refuses them too; /health stays open as a liveness probe.
func TestMetadataEndpointsRespectPolicy(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, "default: deny\n")
	for _, path := range []string{"/label/list", "/inspect?token=vault://x"} {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s under default:deny → %d, want 403", path, resp.StatusCode)
		}
	}
	resp, err := ts.Client().Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health should stay available as a liveness probe, got %d", resp.StatusCode)
	}
}

func TestPolicyDeniesGrantWithoutBurningIt(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - action: grant
    min_risk: critical
    effect: deny
    reason: critical data may not be delegated
`)
	token := storeSSN(t, ts)
	code, body := post(t, ts, "/grant", map[string]interface{}{
		"token": token, "grantor_agent": "a", "grantee_agent": "b",
	}, "")
	if code != 403 {
		t.Fatalf("grant of critical entry should 403: %d %v", code, body)
	}
	if body["grant_id"] != nil {
		t.Fatal("no grant should have been created")
	}
}

// A policy denial on grant-based retrieval must not consume the single-use
// grant: fix the policy, retry, the grant still redeems.
func TestPolicyDenialPreservesGrant(t *testing.T) {
	dir := t.TempDir()
	// Build the server by hand so we can rewrite the policy file mid-test.
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(polPath, []byte("rules: [{action: retrieve, min_risk: critical, effect: deny}]"), 0600)
	srv := server.New(classifier.New(nil), vlt, auditL)
	srv.SetPolicyEngine(policy.NewEngine(polPath))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); auditL.Close(); vlt.Close() })

	token := storeSSN(t, ts)
	_, g := post(t, ts, "/grant", map[string]interface{}{
		"token": token, "grantor_agent": "a", "grantee_agent": "b", "allowed_tool": "lookup",
	}, "")
	grantID, _ := g["grant_id"].(string)
	if grantID == "" {
		t.Fatalf("grant not created: %v", g)
	}

	req := map[string]string{"grant_id": grantID, "agent_id": "b", "requesting_tool": "lookup"}
	if code, _ := post(t, ts, "/retrieve", req, ""); code != 403 {
		t.Fatalf("expected policy denial, got %d", code)
	}

	// Loosen the policy; the same grant must still be redeemable.
	os.WriteFile(polPath, []byte("rules: []\n# reload marker"), 0600)
	code, out := post(t, ts, "/retrieve", req, "")
	if code != 200 || out["value"] != "429-21-0001" {
		t.Fatalf("grant should have survived the earlier denial: %d %v", code, out)
	}
}

// /label/get returns raw values, so it must sit behind the same policy gate
// as /assume — otherwise it is a bypass.
func TestPolicyGatesLabelGet(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: assume
    provider: aws
    effect: deny
    reason: aws is locked down
`)
	seedAWSCreds(t, vlt)

	resp, err := ts.Client().Get(ts.URL + "/label/get?name=aws:default")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("label/get should be policy-gated like assume: got %d", resp.StatusCode)
	}
}

// agentKey mints a verified key so /assume attributes the right agent.
func agentKey(t *testing.T, vlt *vault.Vault, agentID string) string {
	t.Helper()
	_, key, err := vlt.CreateAgentKey(agentID)
	if err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	return key
}

// seedAWSCreds vaults a minimal aws:default credential map so /assume has
// something to resolve if policy lets it through.
func seedAWSCreds(t *testing.T, vlt *vault.Vault) {
	t.Helper()
	tok1, err := vlt.Store("AKIAIOSFODNN7EXAMPLE", "AWSAPIKey", "critical", "seeder", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := vlt.Store("wJalrXUtnFEMI/K7MDENG", "Credential", "critical", "seeder", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	mapTok, err := vlt.Store(
		`{"aws_access_key_id":"`+tok1+`","aws_secret_access_key":"`+tok2+`"}`,
		"CredentialMap", "critical", "seeder", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("aws:default", mapTok); err != nil {
		t.Fatal(err)
	}
	// aws delivers a credential, so it must be trusted before /assume applies it;
	// these tests exercise the policy gate, not the trust gate.
	trustBundle(t)
}
