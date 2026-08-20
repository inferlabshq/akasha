package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// TestAssumeBrokersFromSource: a source-backed provider's credential is fetched
// live from its backend on /assume (broker), trust-gated — never read from the
// vault. This is the agent payoff: the secret stays in the upstream manager.
func TestAssumeBrokersFromSource(t *testing.T) {
	bindir := t.TempDir()
	op := filepath.Join(bindir, "op")
	if err := os.WriteFile(op, []byte("#!/bin/sh\nprintf '%s' 'brokered-dd-key'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_OP_BIN", op)

	tdir := t.TempDir()
	os.WriteFile(filepath.Join(tdir, "ddtest.yaml"), []byte(`
kind: provider
name: ddtest
version: 1
credential: {fields: {api_key: {secret: true}}}
source:
  - backend: onepassword-cli
    ref: "op://Eng/dd/{instance}/credential"
    map: {value: api_key}
deliver: [{mode: env, env: {DD_API_KEY: "{api_key}"}}]
`), 0600)
	t.Setenv("AKASHA_TEMPLATES_PATH", tdir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	store, _ := trust.Load()
	if err := store.Approve(template.Get("ddtest")); err != nil {
		t.Fatal(err)
	}
	store.Save()

	ts, _ := newTestServer(t)

	// Trusted → brokered live, delivered as env. No vault label exists for it.
	code, out := post(t, ts, "/assume", map[string]string{"provider": "ddtest", "profile": "default"}, "")
	if code != 200 {
		t.Fatalf("broker assume failed: %d %v", code, out)
	}
	env, _ := out["env"].(map[string]interface{})
	if env["DD_API_KEY"] != "brokered-dd-key" {
		t.Fatalf("brokered secret not delivered: %v", out)
	}

	// Revoke trust → running the backend is refused (403).
	store.Revoke("ddtest")
	store.Save()
	code2, _ := post(t, ts, "/assume", map[string]string{"provider": "ddtest", "profile": "default"}, "")
	if code2 != http.StatusForbidden {
		t.Fatalf("untrusted broker should be 403, got %d", code2)
	}
}

// trustBundle records hash-bound approval for every loaded provider — standing
// in for the one-time bundle approval `akasha setup` performs. Assumable
// templates are gated on trust, so a test that exercises /assume must establish
// it first (unless it is specifically testing the untrusted path).
func trustBundle(t *testing.T) {
	t.Helper()
	if os.Getenv("AKASHA_APPROVALS_FILE") == "" {
		t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "approvals.json"))
	}
	if os.Getenv("AKASHA_PUBLISHERS_FILE") == "" {
		t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "publishers.json"))
	}
	store, err := trust.Load()
	if err != nil {
		t.Fatalf("trust.Load: %v", err)
	}
	for _, tp := range template.Providers() {
		if err := store.Approve(tp); err != nil {
			t.Fatalf("approve %s: %v", tp.Name, err)
		}
	}
	if err := store.Save(); err != nil {
		t.Fatalf("save approvals: %v", err)
	}
}

// humanServer wraps a test server so ts.Client() authenticates as the local
// human CLI, and returns it.
//
// Nearly every test in this package predates authentication being mandatory:
// they sent no X-Akasha-Key and were served, because a keyless caller used to
// be TAKEN FOR the human. The daemon now refuses unauthenticated callers
// outright, so those requests would all 401 — not because the behaviour under
// test changed, but because the identity they were implicitly relying on now
// has to be presented.
//
// Attaching the CLI key in the transport says what those tests always meant
// ("this is the human calling") in one place, instead of threading a key
// through ~70 call sites and burying the change. Two properties keep it honest:
//
//   - A request that sets its own X-Akasha-Key is left alone, so tests that
//     exercise agent identity still do.
//   - It is opt-IN per request. A test that means to send NO key uses a plain
//     http.Client against ts.URL and gets a genuinely anonymous request — which
//     is exactly what the keyless-refusal tests in revocation_test.go do.
func humanServer(t *testing.T, ts *httptest.Server, vlt *vault.Vault) *httptest.Server {
	t.Helper()
	_, key, err := vlt.MintReservedAgentKey(vault.IdentityCLI)
	if err != nil {
		t.Fatalf("mint cli key: %v", err)
	}
	inner := ts.Client().Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	ts.Client().Transport = &cliKeyTransport{inner: inner, key: key}
	return ts
}

// cliKeyTransport adds the CLI key to any request that does not already carry
// an identity.
type cliKeyTransport struct {
	inner http.RoundTripper
	key   string
}

func (t *cliKeyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("X-Akasha-Key") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("X-Akasha-Key", t.key)
	}
	return t.inner.RoundTrip(r)
}

// newTestServer spins up the real handler stack backed by a temp vault.
func newTestServer(t *testing.T) (*httptest.Server, *vault.Vault) {
	t.Helper()
	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(classifier.New(nil), vlt, auditL)

	// Isolate the policy engine to this test's temp dir. server.New defaults to
	// policy.DefaultPath() (~/.akasha/policy.yaml), so without this every test
	// here evaluates against whatever policy the developer happens to have
	// installed: a restrictive local file fails unrelated tests, an "ask" rule
	// hangs the suite on a GUI dialog, and CI exercises a policy no user has.
	// The path is deliberately left non-existent, which the engine treats as
	// allow-all — the right neutral baseline for tests that are not about
	// policy. Tests that ARE about policy install their own engine and file
	// (see policy_gate_test.go).
	srv.SetPolicyEngine(policy.NewEngine(filepath.Join(dir, "policy.yaml")))

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); auditL.Close(); vlt.Close() })
	return humanServer(t, ts, vlt), vlt
}

func post(t *testing.T, ts *httptest.Server, path string, body interface{}, key string) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Akasha-Key", key)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// ─── /wrap + /retrieve ────────────────────────────────────────────────────

func TestWrapVaultsSensitiveContent(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := post(t, ts, "/wrap", map[string]string{
		"agent_id": "a", "tool_name": "lookup", "content": "SSN 429-21-0001",
	}, "")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if out["vaulted"] != true {
		t.Fatalf("expected vaulted: %v", out)
	}
	if out["category"] != "SSN" {
		t.Fatalf("category: %v", out["category"])
	}
	if out["clean_content"] == "SSN 429-21-0001" {
		t.Fatal("clean_content should have the SSN replaced")
	}
}

// A payload with multiple distinct secrets must have EVERY one vaulted and
// redacted — not just the first match (finding #3).
func TestWrapRedactsEverySecret(t *testing.T) {
	ts, vlt := newTestServer(t)
	content := "key AKIAIOSFODNN7EXAMPLE ssn 429-21-0001 done"
	code, out := post(t, ts, "/wrap", map[string]string{
		"agent_id": "a", "tool_name": "send", "content": content,
	}, "")
	if code != 200 {
		t.Fatalf("wrap failed: %d %v", code, out)
	}
	clean, _ := out["clean_content"].(string)
	if strings.Contains(clean, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(clean, "429-21-0001") {
		t.Fatalf("a secret leaked into clean_content: %q", clean)
	}
	toks, _ := out["tokens"].([]interface{})
	if len(toks) < 2 {
		t.Fatalf("expected >=2 tokens, got %v", out["tokens"])
	}
	covered := map[string]bool{}
	for _, ti := range toks {
		tok, _ := ti.(string)
		if !strings.Contains(clean, tok) {
			t.Fatalf("token %q not embedded in clean_content %q", tok, clean)
		}
		val, err := vlt.Retrieve(tok, "test")
		if err != nil {
			t.Fatalf("retrieve %s: %v", tok, err)
		}
		covered[val] = true
	}
	if !covered["AKIAIOSFODNN7EXAMPLE"] || !covered["429-21-0001"] {
		t.Fatalf("vaulted tokens did not cover both secrets: %v", covered)
	}
}

func TestStoreRetrieveRoundtrip(t *testing.T) {
	ts, _ := newTestServer(t)
	_, st := post(t, ts, "/store", map[string]string{
		"agent_id": "a", "content": "topsecret", "category": "APIKey", "risk": "critical",
	}, "")
	token, _ := st["token"].(string)
	if token == "" {
		t.Fatal("no token from /store")
	}
	code, rt := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "a", "requesting_tool": "x",
	}, "")
	if code != 200 || rt["value"] != "topsecret" {
		t.Fatalf("retrieve failed: %d %v", code, rt)
	}
}

// ─── auth middleware ──────────────────────────────────────────────────────

func TestAuthKeylessAllowed(t *testing.T) {
	ts, _ := newTestServer(t)
	// No key header → request still proceeds (advisory model).
	code, _ := post(t, ts, "/store", map[string]string{
		"agent_id": "a", "content": "x", "category": "c", "risk": "low",
	}, "")
	if code != 200 {
		t.Fatalf("keyless should be allowed, got %d", code)
	}
}

func TestAuthInvalidKeyRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	code, _ := post(t, ts, "/store", map[string]string{
		"agent_id": "a", "content": "x", "category": "c", "risk": "low",
	}, "agt_does_not_exist")
	if code != http.StatusUnauthorized {
		t.Fatalf("invalid key should be 401, got %d", code)
	}
}

func TestAuthValidKeyOverridesAgentID(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, key, err := vlt.CreateAgentKey("real-agent")
	if err != nil {
		t.Fatal(err)
	}
	// Body claims a different agent; the verified key must win.
	_, out := post(t, ts, "/store", map[string]string{
		"agent_id": "i-am-lying", "content": "x", "category": "c", "risk": "low",
	}, key)
	token, _ := out["token"].(string)
	entry, err := vlt.Inspect(token)
	if err != nil {
		t.Fatal(err)
	}
	if entry.AgentID != "real-agent" {
		t.Fatalf("agent_id should be verified identity 'real-agent', got %q", entry.AgentID)
	}
}

// ─── /grant + grant-based /retrieve ───────────────────────────────────────

func TestGrantRedemption(t *testing.T) {
	ts, vlt := newTestServer(t)
	// The grantee authenticates as itself. It used to redeem by TYPING
	// "agent_id":"b" on an unauthenticated request, which the daemon believed —
	// so a grant naming "b" was redeemable by anyone willing to write the name.
	// Now the identity comes from the key, and the body field is ignored.
	_, keyB, err := vlt.CreateAgentKey("b")
	if err != nil {
		t.Fatal(err)
	}
	_, st := post(t, ts, "/store", map[string]string{
		"agent_id": "a", "content": "card-1234", "category": "CreditCard", "risk": "critical",
	}, "")
	token := st["token"].(string)

	_, g := post(t, ts, "/grant", map[string]interface{}{
		"token": token, "grantor_agent": "a", "grantee_agent": "b",
		"allowed_tool": "charge", "ttl_seconds": 300,
	}, "")
	grantID, _ := g["grant_id"].(string)
	if grantID == "" {
		t.Fatal("no grant_id")
	}

	// b redeems via /retrieve with the grant
	code, rt := post(t, ts, "/retrieve", map[string]string{
		"grant_id": grantID, "requesting_tool": "charge",
	}, keyB)
	if code != 200 || rt["value"] != "card-1234" {
		t.Fatalf("grant redeem failed: %d %v", code, rt)
	}

	// single-use: second redeem denied
	code2, _ := post(t, ts, "/retrieve", map[string]string{
		"grant_id": grantID, "requesting_tool": "charge",
	}, keyB)
	if code2 == 200 {
		t.Fatal("grant should be single-use")
	}
}

// ─── /assume path-traversal guard at the HTTP layer ───────────────────────

func TestAssumeRejectsTraversalProfile(t *testing.T) {
	ts, vlt := newTestServer(t)
	// Seed a real credential map + a malicious label pointing at it.
	akTok, _ := vlt.Store("AKIA", "AWSAccessKeyID", "critical", "a", "t", 0)
	skTok, _ := vlt.Store("secret", "AWSSecretKey", "critical", "a", "t", 0)
	mapJSON := `{"access_key_id":"` + akTok + `","secret_access_key":"` + skTok + `"}`
	mapTok, _ := vlt.Store(mapJSON, "AWSCredentialMap", "critical", "a", "t", 0)
	vlt.SetLabel("aws:../../evil", mapTok)

	code, out := post(t, ts, "/assume", map[string]string{
		"provider": "aws", "profile": "../../evil",
	}, "")
	if code < 400 {
		t.Fatalf("traversal profile should be rejected, got %d %v", code, out)
	}
	// And no file should exist outside the sessions dir.
	home, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(home, ".akasha", "evil.creds")); err == nil {
		t.Fatal("traversal wrote a file outside sessions dir")
	}
}

func TestAssumeHappyPath(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	akTok, _ := vlt.Store("AKIAEXAMPLE", "AWSAccessKeyID", "critical", "a", "t", 0)
	skTok, _ := vlt.Store("secretval", "AWSSecretKey", "critical", "a", "t", 0)
	mapJSON := `{"access_key_id":"` + akTok + `","secret_access_key":"` + skTok + `"}`
	mapTok, _ := vlt.Store(mapJSON, "AWSCredentialMap", "critical", "a", "t", 0)
	vlt.SetLabel("aws:default", mapTok)

	code, out := post(t, ts, "/assume", map[string]string{
		"provider": "aws", "profile": "default",
	}, "")
	if code != 200 {
		t.Fatalf("assume failed: %d %v", code, out)
	}
	env, _ := out["env"].(map[string]interface{})
	path, _ := env["AWS_SHARED_CREDENTIALS_FILE"].(string)
	if path == "" {
		t.Fatalf("no credentials file path: %v", out)
	}
	defer os.Remove(path)
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte("AKIAEXAMPLE")) {
		t.Fatal("credentials file missing the access key")
	}
}

// ─── label + profile + inspect + purge handlers ──────────────────────────

func TestLabelSetGetList(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("val", "APIKey", "high", "a", "t", 0)

	if code, _ := post(t, ts, "/label/set", map[string]string{"name": "svc:x", "token": tok}, ""); code != 200 {
		t.Fatalf("label/set: %d", code)
	}
	// credential/retrieve resolves to the decrypted value
	resp, _ := ts.Client().Get(ts.URL + "/credential/retrieve?name=svc:x")
	var got map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["value"] != "val" {
		t.Fatalf("credential/retrieve value: %v", got)
	}
	// label/list with prefix
	resp2, _ := ts.Client().Get(ts.URL + "/label/list?prefix=svc:")
	var names []string
	json.NewDecoder(resp2.Body).Decode(&names)
	resp2.Body.Close()
	if len(names) != 1 || names[0] != "svc:x" {
		t.Fatalf("label/list: %v", names)
	}
}

func TestLabelSetMissingFields(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := post(t, ts, "/label/set", map[string]string{"name": "x"}, ""); code != 400 {
		t.Fatalf("expected 400 for missing token, got %d", code)
	}
}

func TestLabelGetMissingAndUnknown(t *testing.T) {
	ts, _ := newTestServer(t)
	r1, _ := ts.Client().Get(ts.URL + "/credential/retrieve")
	r1.Body.Close()
	if r1.StatusCode != 400 {
		t.Fatalf("missing name should be 400, got %d", r1.StatusCode)
	}
	r2, _ := ts.Client().Get(ts.URL + "/credential/retrieve?name=nope")
	r2.Body.Close()
	if r2.StatusCode != 404 {
		t.Fatalf("unknown label should be 404, got %d", r2.StatusCode)
	}
}

func TestInspectTokenAndGrantAndMissing(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("secret", "SSN", "critical", "agent-x", "lookup", 0)

	r, _ := ts.Client().Get(ts.URL + "/inspect?token=" + tok)
	var e map[string]interface{}
	json.NewDecoder(r.Body).Decode(&e)
	r.Body.Close()
	if e["Category"] != "SSN" {
		t.Fatalf("inspect token: %v", e)
	}

	// grant inspect
	gid, _ := vlt.CreateGrant(tok, "a", "b", "t", "task", 0)
	rg, _ := ts.Client().Get(ts.URL + "/inspect?grant_id=" + gid)
	rg.Body.Close()
	if rg.StatusCode != 200 {
		t.Fatalf("inspect grant: %d", rg.StatusCode)
	}

	// missing args + unknown token
	rm, _ := ts.Client().Get(ts.URL + "/inspect")
	rm.Body.Close()
	if rm.StatusCode != 400 {
		t.Fatalf("inspect no args: %d", rm.StatusCode)
	}
	ru, _ := ts.Client().Get(ts.URL + "/inspect?token=vault://nope")
	ru.Body.Close()
	if ru.StatusCode != 404 {
		t.Fatalf("inspect unknown: %d", ru.StatusCode)
	}
}

func TestProfileSaveAndPurge(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("v", "AWSCredentialMap", "critical", "a", "t", 0)
	if code, _ := post(t, ts, "/profile/save", map[string]interface{}{
		"provider": "aws", "profile": "default", "token": tok,
		"metadata": map[string]string{"region": "us-east-1"},
	}, ""); code != 200 {
		t.Fatalf("profile/save: %d", code)
	}
	if code, _ := post(t, ts, "/profile/save", map[string]interface{}{"provider": "aws"}, ""); code != 400 {
		t.Fatalf("profile/save missing fields should 400, got %d", code)
	}
	if code, _ := post(t, ts, "/vault/purge", map[string]interface{}{}, ""); code != 200 {
		t.Fatalf("vault/purge: %d", code)
	}
}

// ─── error branches on the core handlers ──────────────────────────────────

func TestErrorBranches(t *testing.T) {
	ts, _ := newTestServer(t)

	// malformed JSON → 400
	for _, p := range []string{"/wrap", "/store", "/retrieve", "/grant", "/assume", "/label/set", "/profile/save"} {
		req, _ := http.NewRequest("POST", ts.URL+p, bytes.NewReader([]byte("{not json")))
		resp, _ := ts.Client().Do(req)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("%s with bad JSON: expected 400, got %d", p, resp.StatusCode)
		}
	}

	// /wrap with non-sensitive content → vaulted:false
	_, out := post(t, ts, "/wrap", map[string]string{"agent_id": "a", "tool_name": "t", "content": "hello world"}, "")
	if out["vaulted"] != false {
		t.Fatalf("clean content should not vault: %v", out)
	}

	// /store missing content → 400
	if code, _ := post(t, ts, "/store", map[string]string{"agent_id": "a"}, ""); code != 400 {
		t.Fatalf("store missing content: %d", code)
	}

	// /retrieve unknown token → 403 denied
	if code, _ := post(t, ts, "/retrieve", map[string]string{"token": "vault://nope", "requesting_tool": "x"}, ""); code != 403 {
		t.Fatalf("retrieve unknown token: %d", code)
	}

	// /retrieve with neither token nor grant → 400
	if code, _ := post(t, ts, "/retrieve", map[string]string{"requesting_tool": "x"}, ""); code != 400 {
		t.Fatalf("retrieve no token/grant: %d", code)
	}

	// /grant on unknown token → 400
	if code, _ := post(t, ts, "/grant", map[string]interface{}{"token": "vault://nope", "grantee_agent": "b"}, ""); code != 400 {
		t.Fatalf("grant unknown token: %d", code)
	}

	// /assume unknown label → 404
	if code, _ := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "ghost"}, ""); code != 404 {
		t.Fatalf("assume unknown profile: %d", code)
	}
	// /assume missing provider → 400
	if code, _ := post(t, ts, "/assume", map[string]string{"profile": "x"}, ""); code != 400 {
		t.Fatalf("assume missing provider: %d", code)
	}
}

// Closing the vault's DB makes every query fail, exercising the
// internal-server-error (500) branches that happy-path tests can't reach.
func TestHandlersOnVaultError(t *testing.T) {
	ts, vlt := newTestServer(t)
	// Seed a label so credential/retrieve reaches the retrieve (then fails on closed DB).
	tok, _ := vlt.Store("v", "APIKey", "high", "a", "t", 0)
	vlt.SetLabel("svc:x", tok)
	vlt.Close() // every subsequent query now errors

	cases := []struct {
		method, path string
		body         interface{}
	}{
		{"POST", "/wrap", map[string]string{"agent_id": "a", "tool_name": "t", "content": "SSN 429-21-0001"}},
		{"POST", "/store", map[string]string{"agent_id": "a", "content": "x", "category": "c", "risk": "low"}},
		{"POST", "/put", map[string]interface{}{"label": "env:x", "fields": map[string]string{"A": "b"}}},
		{"POST", "/profile/save", map[string]interface{}{"provider": "p", "profile": "q", "token": tok}},
		{"POST", "/vault/purge", map[string]interface{}{}},
		{"POST", "/label/set", map[string]string{"name": "n", "token": tok}},
		{"GET", "/label/list?prefix=svc:", nil},
		// note: /credential/retrieve maps a DB error to 404 (covered elsewhere), so it's
		// intentionally not asserted as 5xx here.
	}
	for _, c := range cases {
		var resp *http.Response
		if c.method == "GET" {
			resp, _ = ts.Client().Get(ts.URL + c.path)
		} else {
			b, _ := json.Marshal(c.body)
			req, _ := http.NewRequest("POST", ts.URL+c.path, bytes.NewReader(b))
			resp, _ = ts.Client().Do(req)
		}
		if resp.StatusCode < 500 {
			t.Fatalf("%s %s on closed vault: expected 5xx, got %d", c.method, c.path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// Remaining handler branches, for full coverage.

func TestWrapRiskyToolNoRegexMatch(t *testing.T) {
	// A watchlisted tool name with non-matching content → Sensitive but empty
	// Value, exercising the storeValue-from-content and clean=content branches.
	ts, _ := newTestServer(t)
	_, out := post(t, ts, "/wrap", map[string]string{
		"agent_id": "a", "tool_name": "charge_card", "content": "just a note",
	}, "")
	if out["vaulted"] != true {
		t.Fatalf("risky tool should vault: %v", out)
	}
	if out["clean_content"] != "just a note" {
		t.Fatalf("risky tool should return content unchanged: %v", out["clean_content"])
	}
}

func TestStoreAppliesDefaults(t *testing.T) {
	// Missing category/risk → defaults (Unknown/high).
	ts, vlt := newTestServer(t)
	_, out := post(t, ts, "/store", map[string]string{"agent_id": "a", "content": "x"}, "")
	tok := out["token"].(string)
	e, _ := vlt.Inspect(tok)
	if e.Category != "Unknown" || e.Risk != "high" {
		t.Fatalf("defaults not applied: cat=%q risk=%q", e.Category, e.Risk)
	}
}

func TestInspectGrantNotFound(t *testing.T) {
	ts, _ := newTestServer(t)
	r, _ := ts.Client().Get(ts.URL + "/inspect?grant_id=grt://nope")
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatalf("unknown grant should be 404, got %d", r.StatusCode)
	}
}

func TestLabelGetRetrieveError(t *testing.T) {
	// Label resolves, but points at a token that doesn't exist → 500.
	ts, vlt := newTestServer(t)
	vlt.SetLabel("svc:dangling", "vault://doesnotexist")
	r, _ := ts.Client().Get(ts.URL + "/credential/retrieve?name=svc:dangling")
	r.Body.Close()
	if r.StatusCode != 500 {
		t.Fatalf("dangling label should be 500, got %d", r.StatusCode)
	}
}

func TestAssumeCorruptMap(t *testing.T) {
	// Label → token whose value is not a JSON credential map → 500.
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("not json at all", "AWSCredentialMap", "critical", "a", "t", 0)
	vlt.SetLabel("aws:corrupt", tok)
	code, _ := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "corrupt"}, "")
	if code != 500 {
		t.Fatalf("corrupt map should be 500, got %d", code)
	}
}

func TestAssumeFieldRetrieveError(t *testing.T) {
	// Valid JSON map, but a field token is dangling → resolve loop errors → 500.
	ts, vlt := newTestServer(t)
	mapJSON := `{"access_key_id":"vault://gone","secret_access_key":"vault://gone2"}`
	tok, _ := vlt.Store(mapJSON, "AWSCredentialMap", "critical", "a", "t", 0)
	vlt.SetLabel("aws:dangling", tok)
	code, _ := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "dangling"}, "")
	if code != 500 {
		t.Fatalf("dangling field token should be 500, got %d", code)
	}
}

func TestAssumeMapTokenRetrieveError(t *testing.T) {
	// Label row exists but points at a token whose vault entry is gone, so the
	// map-token Retrieve fails → 500.
	ts, vlt := newTestServer(t)
	vlt.SetLabel("aws:ghost", "vault://nonexistent")
	code, _ := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "ghost"}, "")
	if code != 500 {
		t.Fatalf("missing map token should be 500, got %d", code)
	}
}

// TestAssumeRequiresTrust pins the "new templates are trusted first" rule: an
// assumable provider is refused until it is approved, then applies passively.
// useUnsignedBundle points the template registry at a copy of the shipped
// bundle with the signatures stripped, and restores it when the test ends.
//
// A test about the trust GATE needs a template nothing has vouched for. Since
// the official key was provisioned the shipped bundle verifies on its own
// signatures, so it can no longer play that part — and clearing
// AKASHA_PUBLISHERS_FILE does not help, because the official root is compiled
// into the binary rather than read from that file.
func useUnsignedBundle(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	src := template.BundleDirForTest()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read shipped bundle: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") { // deliberately drops the .yaml.sig files
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	os.Setenv("AKASHA_TEMPLATES_PATH", dir)
	template.ResetForTest()
	t.Cleanup(func() {
		os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
		template.ResetForTest()
	})
}

func TestAssumeRequiresTrust(t *testing.T) {
	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "approvals.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "publishers.json"))
	useUnsignedBundle(t)
	ts, vlt := newTestServer(t)
	akTok, _ := vlt.Store("AKIAEXAMPLE", "AWSAccessKeyID", "critical", "a", "t", 0)
	skTok, _ := vlt.Store("secretval", "AWSSecretKey", "critical", "a", "t", 0)
	mapTok, _ := vlt.Store(`{"access_key_id":"`+akTok+`","secret_access_key":"`+skTok+`"}`,
		"AWSCredentialMap", "critical", "a", "t", 0)
	vlt.SetLabel("aws:default", mapTok)

	// Untrusted → refused.
	if code, _ := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, ""); code != http.StatusForbidden {
		t.Fatalf("untrusted assume should be 403, got %d", code)
	}

	// Approve once (what setup / `akasha template trust` does) → applies.
	store, err := trust.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(template.Get("aws")); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	if code, out := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, ""); code != 200 {
		t.Fatalf("trusted assume should be 200, got %d %v", code, out)
	}
}

func TestAssumeWriteError(t *testing.T) {
	// Map resolves fine, but is missing a field the provider requires, so
	// assume.Write fails → 400 (the post-resolution error branch).
	ts, vlt := newTestServer(t)
	trustBundle(t)
	akTok, _ := vlt.Store("AKIA", "AWSAccessKeyID", "critical", "a", "t", 0)
	mapJSON := `{"access_key_id":"` + akTok + `"}` // no secret_access_key
	tok, _ := vlt.Store(mapJSON, "AWSCredentialMap", "critical", "a", "t", 0)
	vlt.SetLabel("aws:onlyak", tok)
	code, _ := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "onlyak"}, "")
	if code != 400 {
		t.Fatalf("incomplete AWS map should be 400, got %d", code)
	}
}

// /put stores an arbitrary secret under a label, and it then assumes via the
// generic env provider — the path for credentials discovery didn't find.
// The agent path (no allow_secret_env) must never receive a raw secret in an env
// var — assume refuses it, so vault_assume can't leak a token to an agent. The
// human/CLI path opts in and gets the value. (finding: env-delivery leak)
func TestAssumeRefusesRawSecretEnvForAgent(t *testing.T) {
	ts, vlt := newTestServer(t)
	post(t, ts, "/put", map[string]interface{}{
		"label": "env:demo", "fields": map[string]string{"API_KEY": "sk_live_x"},
		"provider": "env", "profile": "demo",
	}, "")

	// A verified agent (presents a valid agent key) is refused a raw secret —
	// gating on identity, not a request flag, so it can't opt in.
	key := agentKey(t, vlt, "some-agent")
	if code, _ := post(t, ts, "/assume", map[string]string{"provider": "env", "profile": "demo"}, key); code != http.StatusForbidden {
		t.Fatalf("verified-agent assume of a raw-secret-env provider should be 403, got %d", code)
	}
	// The human CLI → the value comes back. ts.Client() presents the CLI key
	// (humanServer); this used to be the KEYLESS case, which is precisely the
	// inversion that was fixed — the privileged path now requires an identity
	// rather than the lack of one.
	code, out := post(t, ts, "/assume", map[string]string{"provider": "env", "profile": "demo"}, "")
	env, _ := out["env"].(map[string]interface{})
	if code != 200 || env["API_KEY"] != "sk_live_x" {
		t.Fatalf("keyless (human) assume should return the value, got %d %v", code, out)
	}
}

func TestPutThenAssumeEnv(t *testing.T) {
	ts, _ := newTestServer(t)

	code, out := post(t, ts, "/put", map[string]interface{}{
		"label":    "env:stripe",
		"fields":   map[string]string{"STRIPE_API_KEY": "sk_live_secret"},
		"provider": "env",
		"profile":  "stripe", // exercises the SaveProfile path too
	}, "")
	if code != 200 || out["token"] == "" {
		t.Fatalf("put failed: %d %v", code, out)
	}

	// Assume it back via the env provider. Keyless (human CLI) → the value comes
	// back as the human CLI; a verified agent would be refused (see
	// TestAssumeRefusesRawSecretEnvForAgent).
	code2, out2 := post(t, ts, "/assume", map[string]string{"provider": "env", "profile": "stripe"}, "")
	if code2 != 200 {
		t.Fatalf("assume env failed: %d %v", code2, out2)
	}
	env, _ := out2["env"].(map[string]interface{})
	if env["STRIPE_API_KEY"] != "sk_live_secret" {
		t.Fatalf("env assume did not return the secret: %v", env)
	}
}

func TestPutValidation(t *testing.T) {
	ts, _ := newTestServer(t)
	// missing fields
	if code, _ := post(t, ts, "/put", map[string]interface{}{"label": "env:x"}, ""); code != 400 {
		t.Fatalf("missing fields should 400, got %d", code)
	}
	// missing label
	if code, _ := post(t, ts, "/put", map[string]interface{}{"fields": map[string]string{"A": "b"}}, ""); code != 400 {
		t.Fatalf("missing label should 400, got %d", code)
	}
	// bad JSON
	req, _ := http.NewRequest("POST", ts.URL+"/put", bytes.NewReader([]byte("{nope")))
	resp, _ := ts.Client().Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("bad JSON should 400, got %d", resp.StatusCode)
	}
}

func TestHealthUnauthenticated(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := ts.Client().Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health should be open, got %d", resp.StatusCode)
	}
}
