package policy

import "testing"

// The property that makes the next forgetful gate safe.
//
// A gate that never resolves a provider must not be able to satisfy an ALLOW
// rule keyed on one, and must not escape a DENY rule keyed on one. This is the
// same asymmetry Category and MinRisk have always had, extended to the two
// facts whose zero value is indistinguishable from a real answer.
func TestUnresolvedProviderFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		doc    string
		want   Effect
		reason string
	}{
		{
			name:   "deny still binds",
			doc:    "default: allow\nrules:\n  - provider: aws\n    effect: deny\n",
			want:   EffectDeny,
			reason: "a gate that did not resolve the provider must not slip past a provider deny",
		},
		{
			name:   "allow does not grant",
			doc:    "default: deny\nrules:\n  - provider: aws\n    effect: allow\n",
			want:   EffectDeny,
			reason: "granting on a condition nobody evaluated is the failure this exists to stop",
		},
		{
			name:   "ask still binds",
			doc:    "default: allow\nrules:\n  - provider: aws\n    effect: ask\n",
			want:   EffectAsk,
			reason: "ask is restrictive; it applies for the same reason deny does",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			// Known is zero: the gate populated nothing.
			got := p.Evaluate(Request{Action: "retrieve", AgentSource: Verified, ToolSource: ServerAssigned})
			if got.Effect != tc.want {
				t.Fatalf("effect = %s, want %s — %s", got.Effect, tc.want, tc.reason)
			}
		})
	}
}

// The other half: a gate that DID look and found no provider is a different
// statement, and a provider-scoped rule must not touch it. Without this, one
// `{provider: aws, effect: deny}` rule would deny every unlabelled secret and
// every vault-wide operation on the machine.
func TestResolvedEmptyProviderIsNotAMatch(t *testing.T) {
	p, err := Parse([]byte("default: allow\nrules:\n  - provider: aws\n    effect: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{
		Action: "retrieve", Category: "SSN", Risk: "critical",
		AgentSource: Verified, ToolSource: ServerAssigned,
		Known: FactProvider | FactInstance,
	})
	if d.Effect != EffectAllow {
		t.Fatalf("an SSN that answers to no provider must not match a provider rule: %+v", d)
	}
}

// Brokerable carries the same trap: false is both "no per-operation route" and
// "nobody consulted the template".
func TestUnresolvedBrokerableFailsClosed(t *testing.T) {
	no := false
	deny := Rule{Brokerable: &no, Effect: EffectDeny}
	allow := Rule{Brokerable: &no, Effect: EffectAllow}
	unresolved := Request{Action: "assume"}

	if !deny.matches(unresolved) {
		t.Error("a deny keyed on brokerable must bind when the template was never consulted")
	}
	if allow.matches(unresolved) {
		t.Error("an allow keyed on brokerable must NOT grant when the template was never consulted")
	}
	resolved := Request{Action: "assume", Known: FactBrokerable}
	if !allow.matches(resolved) {
		t.Error("once the template is consulted, an allow may grant")
	}
}
