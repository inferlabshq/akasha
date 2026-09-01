package policy

import "testing"

// A caller-asserted identity may narrow a deny but must never satisfy an allow.
// These pin each half of that rule, plus the distinction that makes it safe to
// apply: most endpoints assign the identity themselves, and those are not
// forgeable.

const agentAllow = `
default: deny
rules:
  - agent: claude
    effect: allow
`

func TestAssertedAgentCannotSatisfyAllow(t *testing.T) {
	p, err := Parse([]byte(agentAllow))
	if err != nil {
		t.Fatal(err)
	}
	// "claude" here came out of the request body — /retrieve's agent_id. Anyone
	// can write it, so it must not open the allow rule.
	if d := p.Evaluate(Request{AgentID: "claude", AgentSource: Asserted}); d.Effect != EffectDeny {
		t.Fatalf("asserted agent id satisfied an allow rule: %+v", d)
	}
}

func TestVerifiedAgentCanSatisfyAllow(t *testing.T) {
	p, err := Parse([]byte(agentAllow))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Request{AgentID: "claude", AgentSource: Verified}); d.Effect != EffectAllow {
		t.Fatalf("key-verified agent should still be granted: %+v", d)
	}
}

// TestServerAssignedAgentCanSatisfyAllow is the non-regression guard.
//
// The obvious version of this change — "keyless callers are untrusted" — would
// break here. Most endpoints ignore the request body and pass a literal the
// daemon picked (akasha-helper on /resolve, akasha-list on /label/list, …).
// Those identities are keyless AND unforgeable, so rules written against them
// must keep granting.
func TestServerAssignedAgentCanSatisfyAllow(t *testing.T) {
	p, err := Parse([]byte(`
default: deny
rules:
  - action: broker
    agent: akasha-helper
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{
		Action:      "broker",
		AgentID:     "akasha-helper",
		AgentSource: ServerAssigned,
	})
	if d.Effect != EffectAllow {
		t.Fatalf("server-assigned identity must still satisfy an allow: %+v", d)
	}
}

func TestAssertedToolCannotSatisfyAllowRule(t *testing.T) {
	p, err := Parse([]byte(`
default: deny
rules:
  - tool: my_tool
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Request{Tool: "my_tool", ToolSource: Asserted}); d.Effect != EffectDeny {
		t.Fatalf("asserted tool satisfied an allow rule: %+v", d)
	}
	if d := p.Evaluate(Request{Tool: "my_tool", ToolSource: ServerAssigned}); d.Effect != EffectAllow {
		t.Fatalf("server-assigned tool should be granted: %+v", d)
	}
}

// TestAssertedMatcherStillNarrowsDeny: restrictive effects are unaffected.
// Matching a deny or ask against a value the caller chose is safe — lying only
// ever costs the caller access.
func TestAssertedMatcherStillNarrowsDeny(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - agent: experiment-bot
    effect: deny
    reason: not this one
  - tool: send_email
    effect: ask
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Request{AgentID: "experiment-bot", AgentSource: Asserted}); d.Effect != EffectDeny {
		t.Fatalf("asserted agent must still match a deny rule: %+v", d)
	}
	if d := p.Evaluate(Request{Tool: "send_email", ToolSource: Asserted}); d.Effect != EffectAsk {
		t.Fatalf("asserted tool must still match an ask rule: %+v", d)
	}
}

// TestUnsetProvenanceIsUntrusted: the zero value is Asserted, so a Request
// built without stating a provenance can only ever be restricted, never
// granted. Forgetting to set it must fail closed.
func TestUnsetProvenanceIsUntrusted(t *testing.T) {
	if Asserted != 0 {
		t.Fatal("Asserted must be the zero value so an unset source fails closed")
	}
	p, err := Parse([]byte(agentAllow))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Request{AgentID: "claude"}); d.Effect != EffectDeny {
		t.Fatalf("a Request with no stated provenance must not be granted: %+v", d)
	}
}

// A rule with no identity matcher is unaffected by provenance — it never
// depended on who the caller claimed to be.
func TestProvenanceIrrelevantWithoutIdentityMatcher(t *testing.T) {
	p, err := Parse([]byte(`
default: deny
rules:
  - action: broker
    provider: github
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{
		Action: "broker", provider: "github", AgentSource: Asserted,
		known: FactProvider | FactInstance,
	})
	if d.Effect != EffectAllow {
		t.Fatalf("a rule keyed only on server-derived fields must still grant: %+v", d)
	}
}
