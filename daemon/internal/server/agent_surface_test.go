package server_test

import (
	"bytes"
	"encoding/json"
	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// keyedPostText posts as a specific identity and returns the raw body, because
// the things under test here ARE the error strings.
func keyedPostText(t *testing.T, ts *httptest.Server, path string, body interface{}, key string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Akasha-Key", key)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

// ─── /store: an agent may not vault a value it invented ───────────────────

// The failure this closes was observed end to end: asked why its AWS calls
// failed, a model called vault_store with the literal string "my_secret_value"
// as an AWSSecretKey and then reported the problem solved. Nothing downstream
// notices — the vault holds a well-formed entry and the audit log records a
// store — so the only place to catch it is at the door.
func TestStoreRefusesAValueAnAgentInvented(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		category string
		content  string
		wants    string // a phrase the refusal must contain
	}{
		{"placeholder", "APIKey", "my_secret_value", "placeholder"},
		{"aws docs example key", "AWSAccessKeyID", "AKIAIOSFODNN7EXAMPLE", "placeholder"},
		{"unfilled variable", "APIKey", "YOUR_ACCESS_KEY_ID", "placeholder"},
		{"wrong shape for the category", "AWSSecretKey", "totally-made-up", "not a AWSSecretKey"},
		{"wrong shape for the category", "AWSAccessKeyID", "AKIAEXAMPLE", "not a AWSAccessKeyID"},
	} {
		code, body := keyedPostText(t, ts, "/store", map[string]string{
			"content": tc.content, "category": tc.category, "risk": "high",
		}, agentKey)
		if code != http.StatusBadRequest {
			t.Errorf("%s: /store %q as %s got %d, want 400\n%s", tc.name, tc.content, tc.category, code, body)
			continue
		}
		if !strings.Contains(body, tc.wants) {
			t.Errorf("%s: refusal does not say why:\n%s", tc.name, body)
		}
	}
}

// A refusal that only says "no" is answered by a model inventing a different
// tool name. Every one of these has to name the call that would have worked.
func TestStoreRefusalNamesTheCallToMakeInstead(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	_, body := keyedPostText(t, ts, "/store", map[string]string{
		"content": "my_secret_value", "category": "AWSSecretKey", "risk": "high",
	}, agentKey)
	if !strings.Contains(body, "vault_status") || !strings.Contains(body, "vault_assume") {
		t.Errorf("a caller with no credential must be routed to vault_status/vault_assume:\n%s", body)
	}

	// ...and never to another way of WRITING. The shape refusal used to end
	// "use vault_put(label=\"provider:profile\", fields={...}) instead", which
	// named the one endpoint that binds a label and handed over the label
	// format with it. Three tool calls then took a made-up key from "vault_store
	// refused this" to aws:default resolving to it, orphaning the user's real
	// credential behind a decoy while the audit log recorded a successful store.
	// A refusal that routes the rejected value to a wider door is worse than no
	// refusal, because it also teaches the shape of the door.
	_, body = keyedPostText(t, ts, "/store", map[string]string{
		"content":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-not-20-chars",
		"category": "AWSAccessKeyID", "risk": "high",
	}, agentKey)
	if strings.Contains(body, "vault_put") {
		t.Errorf("the refusal must not hand the value it just rejected the label-binding door:\n%s", body)
	}
	if !strings.Contains(body, "vault_status") {
		t.Errorf("the refusal must still name a next call — vault_status is the one that answers:\n%s", body)
	}
}

// The guard is agent-only, and that is the half most likely to be broken by a
// future tightening. `akasha protect` pushes whole credential FILES through
// this endpoint, and `akasha discover` pushes whatever is actually in the
// user's config — including the deliberately unreal keys a LocalStack or MinIO
// setup uses. The person at the keyboard is allowed to vault a value that does
// not look like a credential.
func TestStoreStillTakesWhateverTheHumanHas(t *testing.T) {
	ts, _ := newTestServer(t)

	for _, tc := range []struct{ category, content string }{
		{"AWSAccessKeyID", "test"},                             // LocalStack
		{"AWSSecretKey", "test"},                               // LocalStack
		{"EscrowedFile", strings.Repeat("x", maxAgentBytes+1)}, // akasha protect
		{"APIKey", "my_secret_value"},
	} {
		code, body := post(t, ts, "/store", map[string]string{
			"content": tc.content, "category": tc.category, "risk": "high",
		}, "")
		if code != http.StatusOK {
			t.Errorf("human /store of a %s got %d, want 200\n%v", tc.category, code, body)
		}
	}
}

// maxAgentBytes mirrors the daemon's cap. Kept as a literal rather than
// exported: the test's job is to notice if the cap moves, not to track it.
const maxAgentBytes = 64 * 1024

func TestStoreCapsWhatAnAgentCanPushIntoTheVault(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	code, body := keyedPostText(t, ts, "/store", map[string]string{
		"content": strings.Repeat("x", maxAgentBytes+1), "category": "APIKey", "risk": "high",
	}, agentKey)
	if code != http.StatusBadRequest {
		t.Fatalf("agent /store of a %d-byte value got %d, want 400\n%s", maxAgentBytes+1, code, body)
	}
	if !strings.Contains(body, "akasha protect") {
		t.Errorf("the refusal should name the command that DOES take a file:\n%s", body)
	}
}

// ─── /put: the sibling door, and the more damaging one ────────────────────

// /store's guard fenced one of two doors. /put takes a whole credential map,
// checked nothing, and ends in SetLabel — so the value /store refused went
// through it and became what the NAME resolves to. Reproduced in three tool
// calls: vault_store{content:"totally-made-up", category:"AWSSecretKey"} → 400,
// vault_put{label:"aws:default", fields:{...same value...}} → 200. Afterwards
// `akasha whoami aws:default`, `akasha helper aws` and `akasha exec --assume
// aws:default` all failed: the user's real credential was still in the vault
// with nothing able to reach it, and the audit log recorded only a successful
// store. A decoy under a token nobody uses is a nuisance; a decoy under the
// name every assume resolves through is an outage.
func TestPutRefusesAValueAnAgentInvented(t *testing.T) {
	trustBundle(t)
	ts, vlt := newTestServer(t)
	seedAWS(t, vlt, "default", testAccount)
	real, err := vlt.GetLabel("aws:default")
	if err != nil {
		t.Fatal(err)
	}
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		fields map[string]string
		wants  string
	}{
		{"the value /store just refused", map[string]string{
			"aws_access_key_id": "totally-made-up", "aws_secret_access_key": "totally-made-up",
		}, "not a AWSAccessKeyID"},
		{"recited from training data", map[string]string{
			"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}, "placeholder"},
		{"an unfilled variable", map[string]string{
			"access_key_id": "YOUR_ACCESS_KEY_ID", "secret_access_key": "<your-secret-here>",
		}, "placeholder"},
		{"a map aws cannot use at all", map[string]string{"k": "v"}, "access_key_id"},
	} {
		code, body := keyedPostText(t, ts, "/put", map[string]interface{}{
			"label": "aws:default", "fields": tc.fields,
		}, agentKey)
		if code != http.StatusBadRequest {
			t.Errorf("%s: agent /put got %d, want 400\n%s", tc.name, code, body)
		}
		if !strings.Contains(body, tc.wants) {
			t.Errorf("%s: refusal does not say why:\n%s", tc.name, body)
		}
		// A caller with no credential is routed to the tools that find and USE
		// the one already vaulted — never to a third way of writing.
		if !strings.Contains(body, "vault_status") {
			t.Errorf("%s: refusal names no next call:\n%s", tc.name, body)
		}
		// The property the guard exists for: the name still resolves to the
		// user's own credential.
		if got, err := vlt.GetLabel("aws:default"); err != nil || got != real {
			t.Fatalf("%s: aws:default was re-pointed anyway (%q → %q, %v)", tc.name, real, got, err)
		}
	}
}

// The guard must not cost /put the flow it exists for: an agent that was handed
// a genuine secret vaults it under a label of its own. Akasha has no opinion
// about the shape of a Stripe key, and an `env:` label names no provider whose
// contract could be checked, so nothing here is refusable.
func TestPutStillTakesASecretAnAgentWasGiven(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	code, body := keyedPostText(t, ts, "/put", map[string]interface{}{
		"label":  "env:stripe",
		"fields": map[string]string{"STRIPE_API_KEY": "sk_live_notarealkey0000000000"},
	}, agentKey)
	if code != http.StatusOK {
		t.Fatalf("agent /put of an arbitrary secret got %d, want 200\n%s", code, body)
	}
}

// And the human half, for the same reason /store keeps it: `akasha discover`
// puts whatever is actually in the user's config, which for a LocalStack or
// MinIO setup is a credential that looks like nothing at all.
func TestPutStillTakesWhateverTheHumanHas(t *testing.T) {
	trustBundle(t)
	ts, _ := newTestServer(t)

	for _, tc := range []struct {
		name   string
		label  string
		fields map[string]string
	}{
		{"LocalStack", "aws:localstack", map[string]string{"access_key_id": "test", "secret_access_key": "test"}},
		{"a map with no provider contract at all", "aws:odd", map[string]string{"k": "v"}},
	} {
		code, body := post(t, ts, "/put", map[string]interface{}{
			"label": tc.label, "fields": tc.fields,
		}, "")
		if code != http.StatusOK {
			t.Errorf("%s: human /put got %d, want 200\n%v", tc.name, code, body)
		}
	}
}

// ─── the arguments a caller gets wrong on its first call ──────────────────

// Missing arguments were 7 of the 21 failed first calls on this surface, and
// the answer was the bare "provider and profile required": it names neither the
// shape it wanted nor a next call, which is the error shape a model answers by
// inventing a tool name rather than by fixing the call. The single-label form
// lands here too — a caller that has seen `aws:default` written anywhere passes
// it as one argument, and being told to split it on the colon is the whole fix.
func TestMissingProviderAndProfileNameTheFormatAndTheNextCall(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	check := func(what, body string) {
		t.Helper()
		for _, want := range []string{"provider=\"aws\"", "profile=\"default\"", "aws:default", "vault_status"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the refusal does not mention %q:\n%s", what, want, body)
			}
		}
	}

	for _, args := range []map[string]string{{}, {"provider": "aws:default"}, {"provider": "aws"}} {
		code, body := keyedPostText(t, ts, "/assume", args, agentKey)
		if code != http.StatusBadRequest {
			t.Fatalf("/assume %v got %d, want 400\n%s", args, code, body)
		}
		check("/assume", body)
	}

	// The GET twin. vault_identity's version of this message was the one on the
	// whole surface that reliably recovered a caller; it must keep saying so.
	for _, q := range []string{"", "?provider=aws", "?provider=aws%3Adefault"} {
		req, _ := http.NewRequest("GET", ts.URL+"/identity"+q, nil)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("/identity%s got %d, want 400\n%s", q, resp.StatusCode, body)
		}
		check("/identity", string(body))
	}
}

// ─── /assume: an unknown provider is a 404, not a misleading 403 ──────────

// `tpl == nil` used to mean two different things — "no such provider" and the
// generic env: provider — and they shared a branch. So a model that guessed
// provider:"s3" was told that S3's credential would come back as a raw secret,
// that S3 had a credential helper, and that vault_retrieve would hand over the
// value: three false statements, the last of which points at the raw-secret
// tool for a credential that does not exist.
func TestAssumeUnknownProviderIs404AndListsWhatExists(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	code, body := keyedPostText(t, ts, "/assume",
		map[string]string{"provider": "s3", "profile": "default"}, agentKey)
	if code != http.StatusNotFound {
		t.Fatalf("assume of an unknown provider got %d, want 404\n%s", code, body)
	}
	if !strings.Contains(body, "aws") {
		t.Errorf("the 404 must name the providers that DO exist:\n%s", body)
	}
	if !strings.Contains(body, "vault_status") {
		t.Errorf("the 404 must name the tool that lists the real pairs:\n%s", body)
	}
	if strings.Contains(body, "vault_retrieve") || strings.Contains(body, "credential helper") {
		t.Errorf("a provider that does not exist has no helper and no value to retrieve:\n%s", body)
	}
}

// The genuine raw-secret refusal must not end by offering the raw-secret tool.
// Naming vault_retrieve there invited the caller to route around the decision
// the daemon had just made; what it can legitimately do is USE the credential
// without seeing it, in a form that survives a stateless shell.
func TestRawSecretRefusalRoutesToUseNotToRetrieve(t *testing.T) {
	ts, vlt := newTestServer(t)
	post(t, ts, "/put", map[string]interface{}{
		"label": "env:app", "fields": map[string]string{"API_KEY": "sk_live_x"},
		"provider": "env", "profile": "app",
	}, "")
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	code, body := keyedPostText(t, ts, "/assume",
		map[string]string{"provider": "env", "profile": "app"}, agentKey)
	if code != http.StatusForbidden {
		t.Fatalf("agent assume of a raw-secret provider got %d, want 403\n%s", code, body)
	}
	if strings.Contains(body, "vault_retrieve") {
		t.Errorf("the refusal must not point at the raw-secret tool it just refused:\n%s", body)
	}
	if !strings.Contains(body, "akasha exec --assume env:app") {
		t.Errorf("the refusal must name the command that brokers it instead:\n%s", body)
	}
}

// ─── the phrases the MCP layer keys on ────────────────────────────────────

// internal/mcp appends its recovery text — "you cannot guess a vault:// token,
// call vault_status" — by matching the daemon's own wording, because a JSON-RPC
// proxy has nothing else to match on: the same 403 covers a policy denial, an
// escrow refusal and a bad token, and only the last of the three should be
// answered with "try a different tool".
//
// That makes these strings a contract rather than prose. Rewording one here
// without updating mcp.tokenHelp would silently drop the help, and the failure
// would be invisible: the call still errors, just uselessly.
func TestTokenErrorWordingTheMCPLayerMatches(t *testing.T) {
	ts, vlt := newTestServer(t)

	if _, body := keyedPostTextHuman(t, ts, "/retrieve", map[string]string{
		"token": "vault://invented", "requesting_tool": "aws",
	}); !strings.Contains(body, "token not found") {
		t.Errorf("/retrieve of an unknown token must still say \"token not found\" — internal/mcp keys on it:\n%s", body)
	}
	if _, body := keyedPostTextHuman(t, ts, "/retrieve", map[string]string{
		"token": "not-a-token", "requesting_tool": "aws",
	}); !strings.Contains(body, "invalid token format") {
		t.Errorf("/retrieve of a malformed token must still say \"invalid token format\":\n%s", body)
	}

	// The other two phrases tokenHelp matches. They were unpinned, which made
	// the pin a fence around half the contract: a reword here would have
	// dropped the help silently, and the call would still error — just
	// uselessly.
	expired, err := vlt.Store("x", "APIKey", "high", "a", "t", time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, body := keyedPostTextHuman(t, ts, "/retrieve", map[string]string{
		"token": expired, "requesting_tool": "aws",
	}); !strings.Contains(body, "token expired") {
		t.Errorf("/retrieve of an expired token must still say \"token expired\":\n%s", body)
	}
	if _, body := keyedPostTextHuman(t, ts, "/retrieve", map[string]string{
		"requesting_tool": "aws",
	}); !strings.Contains(body, "token or grant_id required") {
		t.Errorf("/retrieve with neither must still say \"token or grant_id required\":\n%s", body)
	}
}

// keyedPostTextHuman is keyedPostText for the CLI identity, which ts.Client()
// carries (see humanServer).
func keyedPostTextHuman(t *testing.T, ts *httptest.Server, path string, body interface{}) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

// The wire contract for the fix to B3. internal/mcp is a verbatim proxy, so
// whatever /assume returns is exactly what the model sees; if run_via is not in
// the daemon's response it is not in the tool result either, and the tool
// description's instruction to "run the returned run_via command" points at a
// field that does not exist.
func TestAssumeReturnsSomethingAStatelessCallerCanRun(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	code, out := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, agentKey)
	if code != http.StatusOK {
		t.Fatalf("agent assume of a file-delivered provider got %d: %v", code, out)
	}
	if out["run_via"] != "akasha exec --assume aws:default -- <your command>" {
		t.Errorf("run_via = %v — an agent that only gets env has no next action", out["run_via"])
	}
	prefix, _ := out["run_prefix"].(string)
	if !strings.Contains(prefix, "AWS_SHARED_CREDENTIALS_FILE=") {
		t.Errorf("run_prefix = %q — it must let the caller apply the credential in one shell call", prefix)
	}
	// Whatever else it carries, it must not carry the secret.
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), secretKeyValue) {
		t.Errorf("the assume response leaked the raw secret:\n%s", blob)
	}
}

// ─── /store: provisioning is exempt by PROVENANCE, not by identity ─────────

// `akasha setup` writes AKASHA_AGENT_KEY into the agent harness's own settings,
// so when the person at the keyboard asks their agent to run `akasha discover`,
// the CLI presents that key and is correctly not the human. Judging the
// exemption on identity therefore refused the user's own `.env` for holding a
// dev password of "password" — with an error blaming a daemon that was running
// and deliberately saying no. What distinguishes these calls is provenance: a
// value akasha itself just read off this machine's disk is the user's, whatever
// it looks like.
func TestStoreAcceptsProvisioningValuesThatLookLikePlaceholders(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	// Every one of these is in the placeholder vocabulary, and every one of
	// them turns up in a real .env as somebody's local dev value.
	for _, value := range []string{"password", "changeme", "secret", "placeholder"} {
		code, body := keyedPostText(t, ts, "/store", map[string]interface{}{
			"agent_id": "akasha-discover", "tool_name": "akasha_provision",
			"content": value, "category": "aws-credential", "risk": "critical",
		}, agentKey)
		if code != http.StatusOK {
			t.Errorf("discovery of %q was refused (%d) — the user's own file is not the agent's invention:\n%s",
				value, code, body)
		}
	}

	// And the half that keeps the guard meaningful: the SAME value from an
	// agent that is not provisioning is still refused.
	code, _ := keyedPostText(t, ts, "/store", map[string]interface{}{
		"agent_id": "claude", "tool_name": "vault_store",
		"content": "password", "category": "aws-credential", "risk": "critical",
	}, agentKey)
	if code != http.StatusBadRequest {
		t.Errorf("an agent inventing a placeholder got %d, want 400 — the exemption is too wide", code)
	}
}

// The size cap is not an opinion about plausibility, so it survives the
// exemption. Nothing that reads a credential off disk needs 200 KiB to do it,
// and bundling the cap in with the value checks gave it up for nothing.
func TestStoreSizeCapAppliesToProvisioningToo(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", 200*1024)

	code, body := keyedPostText(t, ts, "/store", map[string]interface{}{
		"agent_id": "akasha-discover", "tool_name": "akasha_provision",
		"content": huge, "category": "aws-credential", "risk": "critical",
	}, agentKey)
	if code != http.StatusBadRequest {
		t.Errorf("a 200 KiB provisioning store got %d, want 400", code)
	}
	if !strings.Contains(body, "not a credential") {
		t.Errorf("refusal should say what the value is, got: %s", body)
	}
}

// ─── The name-ownership rules, each with a test that bites ─────────────────
//
// Three bypasses shipped in this area before anything covered it, and every one
// survived a full `go test ./...`. These are the call-site assertions: not "the
// helper works" but "the endpoint uses it".

// An agent may add a name. It may not take one over.
func TestAgentCannotRepointAnExistingLabel(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	_, human := keyedPostTextHuman(t, ts, "/store", map[string]interface{}{
		"agent_id": "cli", "tool_name": "akasha_put", "content": "ghp_HUMANhumanHUMANhumanHUMANhuman01",
		"category": "github-credential", "risk": "critical",
	})
	humanTok := tokenFrom(t, human)
	if code, body := keyedPostTextHuman(t, ts, "/label/set", map[string]interface{}{
		"name": "github:default", "token": humanTok,
	}); code != http.StatusOK {
		t.Fatalf("the human should be able to bind: %d %s", code, body)
	}

	// The agent vaults something of its own — allowed — and tries to move the
	// human's name onto it.
	_, agent := keyedPostText(t, ts, "/store", map[string]interface{}{
		"agent_id": "claude", "tool_name": "vault_store", "content": "ghp_AGENTagentAGENTagentAGENTage01",
		"category": "github-credential", "risk": "critical",
	}, agentKey)
	agentTok := tokenFrom(t, agent)

	code, body := keyedPostText(t, ts, "/label/set", map[string]interface{}{
		"name": "github:default", "token": agentTok,
	}, agentKey)
	if code != http.StatusForbidden {
		t.Errorf("agent re-point got %d, want 403\n%s", code, body)
	}

	// A name of its OWN is fine — refusing that would push callers toward
	// reusing a name that already exists, which is the thing being stopped.
	if code, body := keyedPostText(t, ts, "/label/set", map[string]interface{}{
		"name": "github:myagent", "token": agentTok,
	}, agentKey); code != http.StatusOK {
		t.Errorf("agent should be able to create its own name: %d %s", code, body)
	}
}

// DELETE plus CREATE is a re-point spelled in two commands, and guarding only
// the one that reads like re-pointing closed nothing: `akasha label rm
// github:default --yes` then `akasha put github:default` moved the name onto an
// agent's own token through the shipped CLI.
func TestAgentCannotDeleteAnExistingLabel(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	_, human := keyedPostTextHuman(t, ts, "/store", map[string]interface{}{
		"agent_id": "cli", "tool_name": "akasha_put", "content": "ghp_HUMANhumanHUMANhumanHUMANhuman01",
		"category": "github-credential", "risk": "critical",
	})
	tok := tokenFrom(t, human)
	keyedPostTextHuman(t, ts, "/label/set", map[string]interface{}{"name": "github:default", "token": tok})

	code, body := keyedPostText(t, ts, "/label/delete", map[string]interface{}{
		"name": "github:default",
	}, agentKey)
	if code != http.StatusForbidden {
		t.Errorf("agent delete of an existing name got %d, want 403\n%s", code, body)
	}

	// Still bound afterwards — the refusal has to be real, not just loud.
	if got, err := vlt.GetLabel("github:default"); err != nil || got != tok {
		t.Errorf("the name was removed anyway: %q %v", got, err)
	}
}

// Provisioning is exempt on both halves, because every discovery run vaults a
// FRESH token for the same credential — so a re-run is a rebind by definition,
// and judging it on identity broke `akasha discover` from an agent session.
func TestProvisioningMayRevaultAnExistingLabel(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	_, first := keyedPostText(t, ts, "/store", map[string]interface{}{
		"agent_id": "akasha-discover", "tool_name": "akasha_provision", "content": "v1",
		"category": "aws-credential", "risk": "critical",
	}, agentKey)
	tok1 := tokenFrom(t, first)
	if code, body := keyedPostText(t, ts, "/label/set", map[string]interface{}{
		"name": "aws:default", "token": tok1, "agent_id": "akasha-discover",
	}, agentKey); code != http.StatusOK {
		t.Fatalf("first discovery bind: %d %s", code, body)
	}

	_, second := keyedPostText(t, ts, "/store", map[string]interface{}{
		"agent_id": "akasha-discover", "tool_name": "akasha_provision", "content": "v2",
		"category": "aws-credential", "risk": "critical",
	}, agentKey)
	tok2 := tokenFrom(t, second)
	if code, body := keyedPostText(t, ts, "/label/set", map[string]interface{}{
		"name": "aws:default", "token": tok2, "agent_id": "akasha-discover",
	}, agentKey); code != http.StatusOK {
		t.Errorf("re-running discovery must not be refused: %d %s", code, body)
	}
}

// The shape check has to judge the name the DELIVERY path will use. Every
// git-family provider declares `token: {aliases: [value]}`, so a caller writing
// {"value": ...} reached a check with an opinion about `token`, found none for
// `value`, and passed — while ResolveCreds mapped it back and re-pointed the
// label anyway. This asserts the ENDPOINT canonicalises, not just that the
// helper can.
func TestPutJudgesAliasedFieldNames(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"value", "token"} {
		code, body := keyedPostText(t, ts, "/put", map[string]interface{}{
			"label": "github:viaalias", "fields": map[string]string{field: "totally-made-up"},
		}, agentKey)
		if code != http.StatusBadRequest {
			t.Errorf("github token under %q got %d, want 400\n%s", field, code, body)
		}
	}
}

// The gate and the lookup must agree on case: the vault resolves prefixes with
// SQL LIKE, which is case-insensitive for ASCII, so a case-SENSITIVE gate let
// `ESCROW:` past while the database still matched it.
func TestEscrowGateIsCaseInsensitive(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"escrow:/tmp/x", "ESCROW:/tmp/x", "Escrow:/tmp/x", "eScRoW:/tmp/x"} {
		code, _ := keyedPostText(t, ts, "/label/set", map[string]interface{}{
			"name": name, "token": "tk_whatever",
		}, agentKey)
		if code != http.StatusForbidden {
			t.Errorf("%q reached the bind path with %d, want 403 — the gate and the lookup disagree", name, code)
		}
	}
}

// tokenFrom pulls the token out of a /store response body.
func tokenFrom(t *testing.T, body string) string {
	t.Helper()
	var res struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil || res.Token == "" {
		t.Fatalf("no token in store response: %s", body)
	}
	return res.Token
}

// The escrow gate has now been found open on a door nobody tested, twice.
//
// First the label test was case-sensitive while the vault's LIKE lookup was not.
// Then the label test was widened and the two call sites comparing a PROVIDER
// directly stayed literal, so `/resolve?provider=ESCROW` kept listing every
// escrowed path. Both times a test existed and covered one door.
//
// So this asserts the property across the doors that consult it, not the helper
// that implements it — including the spelling that walked past the last fix.
func TestEscrowGateHoldsOnEveryDoor(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	// There has to be something to leak. A gate tested against an EMPTY vault
	// answers "nothing is vaulted" whether it is working or not — which is how
	// the first version of this test passed with the fix reverted, and the same
	// shape of hole it was written to catch.
	secretPath := "/home/someone/.aws/" + "credentials"
	tok, err := vlt.Store("ACCESS-KEY-CANARY", escrow.Category, "critical", "cli", "akasha_protect", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel(escrow.LabelPrefix+secretPath, tok); err != nil {
		t.Fatal(err)
	}

	for _, spelling := range []string{"escrow", "ESCROW", "Escrow", "eScRoW"} {
		// /resolve takes a PROVIDER, which is the door the label-shaped test
		// could not reach. A denied caller must learn nothing about which
		// escrowed paths exist.
		code, body := keyedGetText(t, ts, "/resolve?provider="+spelling+"&instance=x", agentKey)
		if code == http.StatusOK && strings.Contains(body, "/") {
			t.Errorf("/resolve?provider=%s handed an agent a path listing (%d):\n%s", spelling, code, body)
		}
		if strings.Contains(body, secretPath) {
			t.Errorf("/resolve?provider=%s enumerated an escrowed path to an agent:\n%s", spelling, body)
		}
		if strings.Contains(body, "ACCESS-KEY-CANARY") {
			t.Errorf("/resolve?provider=%s leaked escrowed CONTENT:\n%s", spelling, body)
		}

		// The broker gate lives in the same handler and takes the same provider,
		// so a named instance must be refused rather than served: an escrowed
		// file has no brokered form, only raw bytes.
		code, body = keyedGetText(t, ts, "/resolve?provider="+spelling+"&instance=default", agentKey)
		if code == http.StatusOK {
			t.Errorf("/resolve?provider=%s&instance=default returned 200 — an escrowed file has no brokered form:\n%s",
				spelling, body)
		}
	}
}

// keyedGetText performs an authenticated GET and returns status and body.
func keyedGetText(t *testing.T, ts *httptest.Server, path, key string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Akasha-Key", key)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
