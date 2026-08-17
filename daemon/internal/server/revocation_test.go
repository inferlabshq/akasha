package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// These tests exist for one defect: authentication used to REDUCE privilege.
//
// `isVerifiedAgent(r)` was true only when a valid agent key produced an agent
// id, so a caller presenting NO key was "not a verified agent" — and the daemon
// read that as the trusted human CLI. The keyless path was therefore not merely
// as privileged as a valid key, it was MORE privileged: it could take raw
// secret delivery through /assume and start an `akasha run`, both of which a
// verified agent was refused.
//
// The consequence, reproduced by hand before this was fixed:
//
//	$ AKASHA_AGENT_KEY=<revoked> akasha whoami aws:pk-website
//	denied: agent key has been revoked
//	$ unset AKASHA_AGENT_KEY && akasha whoami aws:pk-website
//	<identity for every AWS credential in the vault>
//
// So `akasha agent revoke` removed an identity while leaving the access path
// open, and the rational move for a compromised agent was to stop
// authenticating. Every test below asserts the inverse property: presenting
// LESS gets you LESS.

// anonGet issues a request carrying no identity at all. It deliberately uses a
// bare client instead of ts.Client(), which humanServer has taught to attach
// the CLI key — the whole point here is that nothing is attached.
func anonGet(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := (&http.Client{}).Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// anonPost is anonGet for write endpoints.
func anonPost(t *testing.T, ts *httptest.Server, path string, body interface{}) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

// keyedGet issues a GET carrying a specific agent key.
func keyedGet(t *testing.T, ts *httptest.Server, path, key string) (int, string) {
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

// TestRevokedAgentCannotRegainAccessByOmittingTheKey is the headline regression.
//
// It walks the exact escalation that was demonstrated: an agent is issued a
// key, the key is revoked, and the agent then retries with the header dropped.
// Before the fix the second call SUCCEEDED — and on /assume it succeeded at a
// higher privilege than the key had ever carried. Both calls must now fail.
//
// /identity is checked first because it is the endpoint the original report
// used (`akasha whoami aws:pk-website`), but the property is asserted across
// every credential-bearing endpoint: a fix that only covered the reported one
// would leave the same door open next to it.
func TestRevokedAgentCannotRegainAccessByOmittingTheKey(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "pk-website", testAccount)

	keyID, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: while the key is live, the agent really can describe the
	// credential. Without this the test could pass because the endpoint is
	// broken rather than because revocation works.
	if code, body := keyedGet(t, ts, "/identity?provider=aws&profile=pk-website", key); code != 200 {
		t.Fatalf("precondition: a live agent key should describe the credential, got %d %s", code, body)
	}

	if err := vlt.RevokeAgentKey(keyID); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/identity?provider=aws&profile=pk-website",
		"/credential/retrieve?name=aws:pk-website",
		"/resolve?provider=aws&instance=pk-website",
		"/label/list?prefix=aws:",
		"/inspect?token=vault://anything",
	} {
		// With the revoked key: refused, as it always was.
		if code, body := keyedGet(t, ts, path, key); code != http.StatusUnauthorized {
			t.Errorf("GET %s with a REVOKED key: got %d, want 401\n%s", path, code, body)
		}
		// With the key dropped: must ALSO be refused. This is the assertion the
		// whole change exists for.
		code, body := anonGet(t, ts, path)
		if code != http.StatusUnauthorized {
			t.Errorf("GET %s with the key OMITTED: got %d, want 401 — dropping the header regained access\n%s",
				path, code, body)
		}
		if strings.Contains(body, secretKeyValue) || strings.Contains(body, "716969406655") {
			t.Errorf("GET %s leaked credential data to an unauthenticated caller:\n%s", path, body)
		}
	}

	for _, tc := range []struct {
		path string
		body interface{}
	}{
		{"/assume", map[string]string{"provider": "aws", "profile": "pk-website"}},
		{"/retrieve", map[string]string{"token": "vault://x", "requesting_tool": "t"}},
		{"/put", map[string]interface{}{"label": "env:x", "fields": map[string]string{"A": "b"}}},
		{"/vault/purge", map[string]interface{}{}},
	} {
		if code, body := anonPost(t, ts, tc.path, tc.body); code != http.StatusUnauthorized {
			t.Errorf("POST %s with the key OMITTED: got %d, want 401\n%s", tc.path, code, body)
		}
	}
}

// The revocation message must not read as an invitation to drop the header. The
// daemon's error text is the most-read documentation it has, and while the
// keyless path was privileged this advice was actively harmful — `akasha
// status` printed a version of it.
func TestRevocationMessageDoesNotSuggestDroppingTheKey(t *testing.T) {
	ts, vlt := newTestServer(t)
	keyID, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.RevokeAgentKey(keyID); err != nil {
		t.Fatal(err)
	}
	_, body := keyedGet(t, ts, "/label/list", key)
	if !strings.Contains(body, "revoked") {
		t.Fatalf("expected a revocation message, got: %s", body)
	}
	if !strings.Contains(body, "unauthenticated caller is refused") {
		t.Errorf("the revocation message should say that dropping the key does not help:\n%s", body)
	}
}

// Privilege must be monotonic in authentication: the raw-secret env path is the
// place the old model inverted it hardest, so it gets its own guard.
//
// `env:` is a provider with no template, which always materializes raw values,
// making it the strongest form of the test.
func TestRawSecretEnvRequiresTheHumanIdentity(t *testing.T) {
	ts, vlt := newTestServer(t)
	post(t, ts, "/put", map[string]interface{}{
		"label": "env:app", "fields": map[string]string{"API_KEY": "sk_live_x"},
		"provider": "env", "profile": "app",
	}, "")
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"provider": "env", "profile": "app"}

	// Anonymous: refused by auth, and in particular NOT mistaken for the human.
	if code, out := anonPost(t, ts, "/assume", body); code != http.StatusUnauthorized {
		t.Errorf("anonymous /assume of a raw-secret provider: got %d, want 401\n%s", code, out)
	}
	// A verified agent: refused, as before.
	if code, _ := post(t, ts, "/assume", body, agentKey); code != http.StatusForbidden {
		t.Errorf("verified agent /assume of a raw-secret provider: got %d, want 403", code)
	}
	// The human CLI: allowed. ts.Client() carries the CLI key (humanServer), so
	// this is the affirmative half — the gate must not have become a blanket
	// refusal that happens to pass the tests above.
	code, out := post(t, ts, "/assume", body, "")
	env, _ := out["env"].(map[string]interface{})
	if code != 200 || env["API_KEY"] != "sk_live_x" {
		t.Errorf("the human CLI must still be able to assume a raw-secret provider: got %d %v", code, out)
	}
}

// `akasha run` had the same inverted gate, with the added insult that its error
// text told the caller to unset AKASHA_AGENT_KEY — i.e. instructed them to take
// the bypass.
func TestRunBeginRequiresTheHumanIdentity(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	code, body := anonPost(t, e.ts, "/run/begin", map[string]interface{}{
		"name": "sneaky", "run_dir": "/tmp",
	})
	if code != http.StatusUnauthorized {
		t.Errorf("anonymous /run/begin: got %d, want 401\n%s", code, body)
	}
	if strings.Contains(body, "unset AKASHA_AGENT_KEY") {
		t.Errorf("the refusal must not advise unsetting the key — that was the bypass:\n%s", body)
	}
}

// The CLI identity is what the human path now hangs on, so a caller must not be
// able to mint a key bearing it. Otherwise the fix is cosmetic: an agent would
// promote itself by asking for the right name.
//
// `agent create` opens the vault directly rather than going through the socket,
// which is why the check lives in the vault and is tested there.
func TestReservedIdentitiesCannotBeMintedByCallers(t *testing.T) {
	ts, vlt := newTestServer(t)
	_ = ts

	for _, id := range []string{
		vault.IdentityCLI,
		"CLI",  // case must not be an escape hatch
		" cli", // nor whitespace
		"run:sneaky",
		"run:",
	} {
		if _, _, err := vlt.CreateAgentKey(id); err == nil {
			t.Errorf("CreateAgentKey(%q) succeeded; a caller minted a reserved identity", id)
		}
		if err := vlt.RegisterAgentKey(id, "agt_forged_"+strings.TrimSpace(id)); err == nil {
			t.Errorf("RegisterAgentKey(%q) succeeded; a reserved identity was re-admitted from a config", id)
		}
	}

	// The daemon's own minting path still works, or `akasha run` and CLI
	// provisioning would both be broken by the guard.
	if _, _, err := vlt.MintReservedAgentKey(vault.IdentityCLI); err != nil {
		t.Errorf("the daemon must still be able to mint its own identities: %v", err)
	}
}

// An agent that steals a DIFFERENT agent's key gets that agent's scope, not the
// human's. This is the "presenting less gets you less" property stated from the
// other side: there is no key whose absence, or whose substitution, produces
// the CLI identity.
func TestAgentKeyNeverResolvesToTheHumanIdentity(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("hunter2", "Generic", "critical", "a", "t", 0)
	if err := vlt.SetLabel("env:app", tok); err != nil {
		t.Fatal(err)
	}
	// An agent whose id merely LOOKS like the CLI's must not be treated as it.
	for _, id := range []string{"cli-helper", "the-cli", "clix"} {
		_, key, err := vlt.CreateAgentKey(id)
		if err != nil {
			t.Fatalf("create %q: %v", id, err)
		}
		if code, _ := post(t, ts, "/assume", map[string]string{
			"provider": "env", "profile": "app",
		}, key); code != http.StatusForbidden {
			t.Errorf("agent %q got the human's raw-secret path: %d, want 403", id, code)
		}
	}
}

// A broken vault must not be reported as a bad key. With every request
// authenticated, an unreadable vault would otherwise turn the entire daemon
// into "your key is wrong" and send users re-minting good keys to chase a
// storage fault.
func TestVaultFailureIsNotReportedAsAnAuthFailure(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	vlt.Close()

	code, body := keyedGet(t, ts, "/label/list", key)
	if code == http.StatusUnauthorized {
		t.Errorf("a closed vault was reported as an auth failure (401); want 5xx:\n%s", body)
	}
	if code < 500 {
		t.Errorf("closed vault: got %d, want 5xx\n%s", code, body)
	}
}
