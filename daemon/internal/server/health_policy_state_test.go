package server_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// /health said "policy: ok" for a machine with no policy file. That machine
// allows everything -- the state in which an agent can take a session credential
// for a provider with a per-operation route -- and the health check reported it
// as fine. A check that only distinguishes "loaded" from "broken" has no word
// for "absent", and absent is the state most new installs were in.
//
// Both helpers authenticate as the local CLI; /health discloses nothing to an
// unidentified caller by design, so an anonymous request would see no policy
// field at all and this test would measure the wrong thing.
func TestHealthDoesNotCallAMissingPolicyOK(t *testing.T) {
	read := func(t *testing.T, url string, get func(string) (map[string]interface{}, error)) string {
		t.Helper()
		body, err := get(url)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := body["policy"].(string)
		return s
	}

	// newTestServer deliberately leaves its policy path non-existent: the
	// never-configured machine.
	ts, _ := newTestServer(t)
	got := read(t, ts.URL+"/health", func(u string) (map[string]interface{}, error) {
		resp, err := ts.Client().Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var m map[string]interface{}
		return m, json.NewDecoder(resp.Body).Decode(&m)
	})
	if !strings.HasPrefix(got, "none") {
		t.Errorf("no policy file exists; health said policy=%q, want a 'none' state — that machine allows everything", got)
	}

	// And with a policy installed it must say ok: the point is to distinguish
	// the states, not to nag forever.
	ts2, _, _ := newPolicyTestServerDir(t, "version: 1\ndefault: allow\nrules: []\n")
	got2 := read(t, ts2.URL+"/health", func(u string) (map[string]interface{}, error) {
		resp, err := ts2.Client().Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var m map[string]interface{}
		return m, json.NewDecoder(resp.Body).Decode(&m)
	})
	if got2 != "ok" {
		t.Errorf("a valid policy is installed; health said policy=%q, want ok", got2)
	}
}
