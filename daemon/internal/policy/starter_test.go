package policy

import "testing"

// The shipped default is a claim, and a claim has to be checked.
//
// Starter is the only policy most machines will ever run: `akasha policy init`
// writes it and `akasha setup` installs it. Its rules are therefore not
// examples — they are the product's default posture, and the assume rule below
// is the whole reason an agent does not get a session credential for a provider
// that has a per-operation route.
//
// Nothing tied that rule to anything. It is a string constant, so it could be
// edited, reordered behind a broader allow, or lost in a merge, and every test
// in the tree would still pass while the default silently became allow-all for
// the case it exists to cover. That is the same shape as a coverage claim
// written in a comment: true when someone wrote it, unverified ever after.
func TestStarterPolicyParsesStrictly(t *testing.T) {
	// Parse, not ParseLenient: `akasha policy validate` is strict, so a starter
	// that only survived the daemon's tolerant path would ship a file the
	// product's own validator rejects.
	p, err := Parse([]byte(Starter))
	if err != nil {
		t.Fatalf("the shipped starter policy does not parse: %v", err)
	}
	for i, r := range p.Rules {
		if u := r.UnknownMatchers(); len(u) > 0 {
			t.Errorf("starter rule %d uses matchers this daemon does not know: %v", i+1, u)
		}
	}
}

// The rule this default exists for, asserted by EVALUATION rather than by
// reading the struct back. A rule can be present and still never fire — shadowed
// by an earlier match, or keyed on a fact nothing resolves — and "the rule is in
// the file" is exactly the kind of assertion that passes while the behaviour is
// gone.
func TestStarterDeniesAgentSessionsOnlyWhereABrokerExists(t *testing.T) {
	p, err := Parse([]byte(Starter))
	if err != nil {
		t.Fatal(err)
	}

	// An agent asking to hold a session credential for a provider that HAS a
	// per-operation route. This is the case the rule is for.
	agentBrokerable := Request{
		Action: "session", AgentID: "claude",
		AgentSource: Verified, ToolSource: ServerAssigned,
		Human:      false,
		brokerable: true,
		known:      FactBrokerable | FactProvider | FactInstance,
	}
	if d := p.Evaluate(agentBrokerable); d.Effect != EffectDeny {
		t.Errorf("an agent assuming a brokerable provider must be denied under the shipped default, got %v (%s)",
			d.Effect, d.Reason)
	}

	// THE SAFETY ASSERTION, and the reason the rule is keyed on `brokerable`
	// rather than on a provider list: ssh and gcp declare only mode:file and no
	// agent block, so there is no other door to send a caller to. Denying them
	// would be a refusal with no fallback, which is how a user learns to switch
	// the policy off entirely.
	agentNoBroker := Request{
		Action: "session", AgentID: "claude",
		AgentSource: Verified, ToolSource: ServerAssigned,
		Human:      false,
		brokerable: false,
		known:      FactBrokerable | FactProvider | FactInstance,
	}
	if d := p.Evaluate(agentNoBroker); d.Effect == EffectDeny {
		t.Errorf("a provider with NO per-operation route must still be assumable — "+
			"refusing it strands the caller with no alternative: %v (%s)", d.Effect, d.Reason)
	}

	// The human is not an agent. `caller: agent` is what keeps the owner able to
	// work on their own machine, and it is server-derived, so a request body
	// cannot claim it.
	human := Request{
		Action: "session", AgentID: "cli",
		AgentSource: Verified, ToolSource: ServerAssigned,
		Human:      true,
		brokerable: true,
		known:      FactBrokerable | FactProvider | FactInstance,
	}
	if d := p.Evaluate(human); d.Effect == EffectDeny {
		t.Errorf("the local human must still be able to take a session credential: %v (%s)",
			d.Effect, d.Reason)
	}

	// A caller still spelling the verb the old way gets the same answer. The
	// starter now says `session`; nothing that said `assume` may fall through
	// to the default.
	aliased := agentBrokerable
	aliased.Action = "assume"
	if d := p.Evaluate(aliased); d.Effect != EffectDeny {
		t.Errorf("a request spelled `assume` slipped past the session rule: %v (%s)", d.Effect, d.Reason)
	}
}

// The other half of the default posture: raw plaintext into a caller's context
// is off. If this stops denying, the broker's whole reason for existing is gone
// and nothing else in the suite would notice.
func TestStarterDeniesRawRetrieve(t *testing.T) {
	p, err := Parse([]byte(Starter))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{
		Action: "retrieve", AgentID: "claude",
		AgentSource: Verified, ToolSource: ServerAssigned,
		known: FactProvider | FactInstance,
	})
	if d.Effect != EffectDeny {
		t.Errorf("the shipped default must deny raw retrieve, got %v (%s)", d.Effect, d.Reason)
	}
}
