package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// The liveness probe must stay answerable without a key, and must not tell an
// unidentified caller how many credentials are in the vault.
//
// Found by running the uninstall test in a second macOS account. The unix
// socket is chmod 0600 and therefore uid-scoped; the loopback TCP listener
// cannot be, because 127.0.0.1 is shared by every account on the machine. So a
// different user ran `akasha status` and was told the size of the first user's
// vault:
//
//	{"status":"ok","vault_expired":0,"vault_total":79}
//
// The same-user ceiling this product documents does not cover that. Its whole
// premise is that an attacker already running as this uid has won anyway — a
// different uid has not.
func TestHealthDoesNotDiscloseVaultSizeToAnUnidentifiedCaller(t *testing.T) {
	ts, vlt := newTestServer(t)
	if _, err := vlt.Store("s3cret", "Credential", "critical", "seed", "seed", 0); err != nil {
		t.Fatal(err)
	}

	get := func(key string) map[string]interface{} {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+"/health", nil)
		if key != "" {
			req.Header.Set("X-Akasha-Key", key)
		}
		// A bare client: ts.Client() carries the CLI key on every request.
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("/health must answer without a key, got %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		var out map[string]interface{}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("health is not JSON: %s", b)
		}
		return out
	}

	anon := get("")
	if anon["status"] != "ok" {
		t.Errorf("liveness must still be answerable without a key: %v", anon)
	}
	if _, ok := anon["vault_total"]; ok {
		t.Errorf("an unidentified caller was told the vault size: %v", anon)
	}
	if _, ok := anon["vault_expired"]; ok {
		t.Errorf("an unidentified caller was told the expiry count: %v", anon)
	}

	// A caller that proves who it is still gets the counts, or `akasha status`
	// silently loses the numbers it exists to print.
	known := get(agentKeyFor(t, vlt, "someone"))
	if _, ok := known["vault_total"]; !ok {
		t.Errorf("an identified caller must still get the counts: %v", known)
	}

	// A bad key is treated as no key: this route grants nothing, so there is no
	// reason to let a caller tell a wrong key from an absent one.
	bad := get("agt_not-a-real-key")
	if _, ok := bad["vault_total"]; ok {
		t.Errorf("an unverifiable key was treated as identified: %v", bad)
	}
}
