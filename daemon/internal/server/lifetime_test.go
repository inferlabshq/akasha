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

// An agent asking for a session credential on a provider that can be brokered
// per operation is routed to that route instead.
//
// The templates already declare the preference — DeliverMode lists modes
// best-first and aws orders helper, describe, file — and nothing consulted it:
// writerFor jumps straight to FileDeliver, so the best route a template declared
// was ignored on the one path that writes plaintext to disk.
func TestAgentIsRoutedToTheBrokerRatherThanGivenASession(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	code, out := post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, agentKey)
	if code != http.StatusForbidden {
		t.Fatalf("agent assume of a brokerable provider got %d, want 403: %v", code, out)
	}

	// A refusal that does not name the recovery is the one that gets worked
	// around. The raw-secret refusal beside this one already sets that bar.
	body := postRaw(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, agentKey)
	for _, want := range []string{"akasha exec --assume aws:default", "per-operation", "akasha helper aws"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not tell the agent how to proceed (missing %q):\n%s", want, body)
		}
	}
}

// The human CLI is unchanged, and so is every provider without a broker route.
// Narrowing the agent path must not narrow the operator's.
func TestHumanAndNonBrokerableProvidersStillAssume(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	seedSSH(t, vlt, "gitlab")

	// Human, brokerable provider: still materialized.
	if code, out := post(t, ts, "/assume",
		map[string]string{"provider": "aws", "profile": "default"}, ""); code != http.StatusOK {
		t.Errorf("the human CLI can no longer assume aws (%d): %v", code, out)
	}

	// Agent, provider with no broker route: still materialized, because there
	// is nowhere else to send it. ssh is the one that matters here — it has no
	// per-operation route and holds the highest-value secret on the box.
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	if code, out := post(t, ts, "/assume",
		map[string]string{"provider": "ssh", "profile": "gitlab"}, agentKey); code != http.StatusOK {
		t.Errorf("an agent can no longer assume ssh, which has no broker route (%d): %v", code, out)
	}
}

// A capability decision that leaves no trace is how this package has been bitten
// before. The attempt happened; the log has to say so.
func TestRoutingRefusalIsAudited(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, "rules: []\n")
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	post(t, ts, "/assume", map[string]string{"provider": "aws", "profile": "default"}, agentKey)

	for _, e := range waitForAudit(t, dir, "DENIED", 1) {
		if !strings.Contains(fmt.Sprint(e["task"]), "Routed aws:default") {
			continue
		}
		if e["category"] != "Credential" {
			t.Errorf("the routing event has no category, so it cannot be filtered: %v", e)
		}
		return
	}
	t.Error("an agent was refused a session credential and nothing named it in the audit log")
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
