package server_test

import (
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// A provider rule must reach the RAW-READ path, not just the broker path.
//
// This is the axis the product is built on: brokered USE may be allowed, raw
// plaintext READ must be deniable. A `provider:` rule that binds on /assume and
// falls through on /retrieve inverts it — the operator writes "aws is off
// limits", the daemon enforces it on the door that hands out no plaintext and
// leaves open the one that does.
func TestProviderRuleReachesRetrieve(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - provider: aws
    effect: deny
    reason: aws is off limits
`)
	seedAWSCreds(t, vlt)

	// A second aws secret, plaintext, so the read path has something to leak.
	tok, err := vlt.Store("AKIA-PLAINTEXT-SECRET", "Credential", "critical", "seeder", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("aws:prod", tok); err != nil {
		t.Fatal(err)
	}

	key := agentKey(t, vlt, "bot")

	// CONTROL — the broker door honours the rule.
	if code, body := post(t, ts, "/assume", map[string]interface{}{
		"provider": "aws", "profile": "default",
	}, key); code != 403 {
		t.Fatalf("CONTROL /assume aws:default: want 403, got %d (%v)", code, body)
	}

	// THE SAME RULE, THE SAME PROVIDER, THE OTHER DOOR.
	code, out := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "bot", "requesting_tool": "lookup",
	}, key)
	if code != 403 {
		t.Fatalf("/retrieve on an aws-labelled secret: want 403, got %d (value=%v)", code, out["value"])
	}
}

// The same asymmetry via the label the caller names, rather than the token.
func TestProviderRuleReachesLabelledRetrieve(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - provider: github
    effect: deny
    reason: github is off limits
`)
	tok, err := vlt.Store("ghp_PLAINTEXT_TOKEN", "Credential", "critical", "seeder", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("github:work", tok); err != nil {
		t.Fatal(err)
	}
	_ = vault.IdentityCLI

	code, out := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "bot", "requesting_tool": "lookup",
	}, agentKey(t, vlt, "bot"))
	if code != 403 {
		t.Fatalf("/retrieve on a github-labelled secret: want 403, got %d (value=%v)", code, out["value"])
	}
}
