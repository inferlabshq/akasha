package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

// postRaw returns the response BODY as text. The shared post() helper decodes
// JSON, and http.Error writes plain text — so a refusal's message, which is the
// thing these tests are about, comes back as an empty map through post().
func postRaw(t *testing.T, ts *httptest.Server, path string, body interface{}, key string) string {
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
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

// The owner's rule, expressed as data: an agent uses a provider per operation
// where one is possible, and the condition comes from the TEMPLATE.
//
// `brokerable` is read from the provider's own declaration — a helper delivery
// plus a vending ownership mechanism — so the rule needs no list of providers
// and cannot go stale when one is added. The daemon evaluates it; it does not
// decide it. Putting this decision in Go would have moved a delivery preference
// out of the templates that declare it, which is not how this system is built.
func TestBrokerableRuleRoutesAgentsWithoutNamingProviders(t *testing.T) {
	ts, vlt, _ := newPolicyTestServerDir(t, `
rules:
  - action: assume
    caller: agent
    brokerable: true
    effect: deny
    reason: use the per-operation route
`)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	seedSSH(t, vlt, "gitlab")
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	// aws declares a per-operation route, so the rule matches.
	if code, _ := post(t, ts, "/assume",
		map[string]string{"provider": "aws", "profile": "default"}, agentKey); code != http.StatusForbidden {
		t.Errorf("agent assume of aws = %d, want 403 from the brokerable rule", code)
	}
	// ssh declares none. The same rule must leave it alone — denying a provider
	// with no alternative would just break it, and the rule names no providers.
	if code, out := post(t, ts, "/assume",
		map[string]string{"provider": "ssh", "profile": "gitlab"}, agentKey); code != http.StatusOK {
		t.Errorf("agent assume of ssh = %d, want 200: ssh has no per-operation route, so the "+
			"rule must not match it (%v)", code, out)
	}
	// And the human is not who the rule is about.
	if code, _ := post(t, ts, "/assume",
		map[string]string{"provider": "aws", "profile": "default"}, ""); code != http.StatusOK {
		t.Errorf("human assume of aws = %d, want 200", code)
	}
}

// The denial still names the route that works — that is what makes it a
// guardrail rather than a wall.
func TestBrokerableDenialNamesTheRoute(t *testing.T) {
	ts, vlt, _ := newPolicyTestServerDir(t, `
rules:
  - action: assume
    brokerable: true
    effect: deny
    reason: use the per-operation route
`)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	body := postRaw(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, "")
	if !strings.Contains(body, "akasha exec --assume aws:default") {
		t.Errorf("a denial on a brokerable provider must name the route that still works:\n%s", body)
	}
}

// With no such rule, nothing is routed. The daemon has no opinion of its own
// about session-versus-per-operation; that is the operator's to state.
func TestWithoutARuleTheDaemonRoutesNothing(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	if code, out := post(t, ts, "/assume",
		map[string]string{"provider": "aws", "profile": "default"}, agentKey); code != http.StatusOK {
		t.Errorf("assume = %d, want 200 — with no policy the daemon must not invent one (%v)", code, out)
	}
}

// The "log to match" half. A credential SUCCESS used to carry no category and no
// risk while the denial carried both — so the successes, which are the ones an
// operator wants to count, were the ones that could not be filtered.
func TestCredentialSuccessesCarryCategoryAndRisk(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, "rules: []\n")
	trustBundle(t)
	seedSSH(t, vlt, "gitlab")

	if code, out := post(t, ts, "/assume",
		map[string]string{"provider": "ssh", "profile": "gitlab"}, ""); code != http.StatusOK {
		t.Fatalf("assume failed: %d %v", code, out)
	}

	for _, e := range waitForAudit(t, dir, "RETRIEVED", 1) {
		if !strings.Contains(fmt.Sprint(e["task"]), "Assume ssh:gitlab") {
			continue
		}
		if e["category"] != "Credential" {
			t.Errorf("category missing from a credential success: %v", e)
		}
		if e["risk"] != "critical" {
			t.Errorf("risk missing from a credential success: %v", e)
		}
		return
	}
	t.Fatal("no success event for the assume at all")
}

// Policy refusing a session handover on a provider that can still be brokered is
// saying "use the other door", and the daemon used to render it as "no".
func TestPolicyDenialNamesTheBrokerRoute(t *testing.T) {
	ts, vlt, _ := newPolicyTestServerDir(t, `
rules:
  - action: assume
    provider: aws
    effect: deny
    reason: production AWS must be brokered per operation
`)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	// As the human, so the routing gate above is not what refuses it.
	body := postRaw(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, "")
	if !strings.Contains(body, "production AWS must be brokered") {
		t.Fatalf("the operator's own reason is missing:\n%s", body)
	}
	if !strings.Contains(body, "akasha exec --assume aws:default") {
		t.Errorf("a denial on a brokerable provider must name the route that still works:\n%s", body)
	}
}

// The TTL a caller asks for is not always the one it gets, and it has to be told.
func TestAssumeClampsTTLAndReportsIt(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedSSH(t, vlt, "gitlab")
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	code, out := post(t, ts, "/assume", map[string]interface{}{
		"provider": "ssh", "profile": "gitlab", "ttl_seconds": 999999999,
	}, agentKey)
	if code != http.StatusOK {
		t.Fatalf("assume failed: %d %v", code, out)
	}
	granted, _ := out["granted_ttl_seconds"].(float64)
	if want := assume.AgentTTLCeiling.Seconds(); granted != want {
		t.Errorf("granted_ttl_seconds = %v, want %v — an agent asked for ~31 years", granted, want)
	}
	notice, _ := out["ttl_notice"].(string)
	if notice == "" {
		t.Error("the TTL was shortened and nothing said so; the file really does vanish early")
	}

	// A request that fits is not annotated, or the notice becomes noise nobody reads.
	_, out2 := post(t, ts, "/assume", map[string]interface{}{
		"provider": "ssh", "profile": "gitlab", "ttl_seconds": 60,
	}, agentKey)
	if n, _ := out2["ttl_notice"].(string); n != "" {
		t.Errorf("a request inside the ceiling was annotated anyway: %q", n)
	}
}
