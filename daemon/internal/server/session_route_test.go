package server_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// /session and /assume are one door with two names. Identical requests must
// get identical answers -- the same refusal for an agent on a raw-secret
// provider, the same success for the human -- and the audit record must name
// the door by what it does, not which spelling was typed.
func TestSessionAndAssumeAreTheSameDoor(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, "rules: []\n")
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)
	if code, out := post(t, ts, "/put", map[string]interface{}{
		"label": "env:app", "fields": map[string]string{"API_KEY": ordinaryValue},
		"provider": "env", "profile": "app",
	}, ""); code != http.StatusOK {
		t.Fatalf("seeding env:app: %d %v", code, out)
	}
	_, agentKey, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	var refusals []string
	for _, route := range []string{"/assume", "/session"} {
		code, body := keyedPostText(t, ts, route, map[string]string{"provider": "env", "profile": "app"}, agentKey)
		if code != http.StatusForbidden {
			t.Errorf("agent %s of env:app: got %d, want 403\n%s", route, code, body)
		}
		refusals = append(refusals, body)
	}
	if len(refusals) == 2 && refusals[0] != refusals[1] {
		t.Errorf("the two spellings refuse differently:\n--- /assume\n%s\n--- /session\n%s", refusals[0], refusals[1])
	}

	for _, route := range []string{"/assume", "/session"} {
		if code, out := post(t, ts, route, map[string]string{"provider": "aws", "profile": "default"}, ""); code != http.StatusOK {
			t.Fatalf("human %s of aws:default: %d %v", route, code, out)
		}
	}
	var sessions int
	for _, e := range waitForAudit(t, dir, "RETRIEVED", 2) {
		if !strings.Contains(fmt.Sprint(e["task"]), "Session aws:default") {
			continue
		}
		sessions++
		if e["agent_id"] != "akasha-assume" {
			t.Errorf("session record carries identity %v, want akasha-assume on both routes", e["agent_id"])
		}
	}
	if sessions != 2 {
		t.Errorf("want 2 Session audit records (one per route), got %d", sessions)
	}
}

// A brokered vend is its own audit action. Until now RETRIEVED covered both a
// raw read and a per-operation broker of the same token, so the log could not
// answer the one question a reviewer asks of it.
func TestBrokeredUseIsAuditedAsBrokeredNotRetrieved(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, "rules: []\n")
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	req, _ := http.NewRequest("GET", ts.URL+"/resolve?provider=aws&instance=default", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/resolve: %d", resp.StatusCode)
	}

	if n := len(waitForAudit(t, dir, "BROKERED", 1)); n < 1 {
		t.Fatal("a /resolve vend wrote no BROKERED record")
	}
	for _, e := range readAuditNow(t, dir) {
		if e["action"] == "RETRIEVED" {
			t.Errorf("a brokered vend was ALSO logged as RETRIEVED -- the two kinds of read are indistinguishable again: %v", e)
		}
	}
}
