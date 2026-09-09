package policy

import (
	"strings"
	"testing"
)

// The polarity of `ask` on a condition this daemon cannot evaluate.
//
// The fail-closed asymmetry — "a restrictive rule matches a condition it could
// not check, a permissive one does not" — was worked out on a two-value ladder
// and then applied to a three-value one. It is right for `deny`, the ceiling: a
// deny that matches more than its author meant can only ever refuse more. It was
// wrong for `ask`, because matching also SHADOWS everything below, and `ask` is
// not a refusal — it is a prompt, and a human clicking Allow on it walked the
// request straight past a deny that would otherwise have fired.
//
// These tests fix the direction: an unreadable condition may only ever make the
// outcome MORE restrictive, which is the property docs/POLICY.md states.

// The reported case: a rule written for a newer daemon.
func TestUnevaluatedAskDoesNotShadowALaterDeny(t *testing.T) {
	p, err := ParseLenient([]byte(`
rules:
  - action: assume
    lifetime: per-command
    effect: ask
    reason: written for a newer daemon
  - action: assume
    provider: aws
    effect: deny
    reason: production is off limits
`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(req("assume", "aws"))
	if d.Effect != EffectDeny {
		t.Fatalf("effect = %s (%s), want deny — an ask rule this daemon could not evaluate "+
			"shadowed the deny below it, and one click would then have allowed the operation",
			d.Effect, d.Reason)
	}
	if !strings.Contains(d.Reason, "production is off limits") {
		t.Errorf("reason = %q, want the deny rule's own reason", d.Reason)
	}
}

// The other half, and the reason the fix is a FLOOR rather than "treat an
// unevaluated ask the way an unevaluated allow is treated". Dropping the rule
// would be a downgrade too: the request would fall through to the default allow
// with nobody asked at all.
func TestUnevaluatedAskStillAsksWhenNothingStricterFollows(t *testing.T) {
	p, err := ParseLenient([]byte(`
rules:
  - action: assume
    lifetime: per-command
    effect: ask
    reason: written for a newer daemon
  - action: assume
    provider: aws
    effect: deny
    reason: production is off limits
`))
	if err != nil {
		t.Fatal(err)
	}
	// gcp: the deny does not apply, so the ask is the strictest thing the file
	// has to say about this request and it must still be honoured.
	d := p.Evaluate(req("assume", "gcp"))
	if d.Effect != EffectAsk {
		t.Fatalf("effect = %s (%s), want ask — an unevaluated ask must not be dropped, "+
			"only outranked", d.Effect, d.Reason)
	}
	if !strings.Contains(d.Reason, "newer daemon") {
		t.Errorf("reason = %q, want the ask rule's own reason so the prompt explains itself", d.Reason)
	}
}

// No later rule is needed for the downgrade: against `default: deny` the
// unevaluated condition alone made a refused request askable.
func TestUnevaluatedAskCannotOutrankTheDefaultDeny(t *testing.T) {
	p, err := ParseLenient([]byte(`
default: deny
rules:
  - action: assume
    lifetime: per-command
    effect: ask
    reason: written for a newer daemon
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(req("assume", "aws")); d.Effect != EffectDeny {
		t.Fatalf("effect = %s (%s), want the default deny — a matcher this daemon cannot read "+
			"made a locked-down policy promptable", d.Effect, d.Reason)
	}
}

// An `ask` whose conditions were all actually CHECKED is untouched: it decides
// the request, first-match-wins, exactly as before. The floor applies to
// unreadable conditions, not to `ask` as an effect.
func TestCheckedAskStillDecidesTheRequest(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - action: assume
    provider: aws
    effect: ask
    reason: approve every production assume
  - action: assume
    effect: deny
    reason: sessions are off
`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(req("assume", "aws"))
	if d.Effect != EffectAsk {
		t.Fatalf("effect = %s (%s), want ask — a fully evaluated ask must still win over "+
			"the deny below it", d.Effect, d.Reason)
	}
	if !strings.Contains(d.Reason, "approve every production assume") {
		t.Errorf("reason = %q, want the ask rule's own reason", d.Reason)
	}
	// And where it genuinely does not apply, the deny below still does.
	if d := p.Evaluate(req("assume", "gcp")); d.Effect != EffectDeny {
		t.Fatalf("effect = %s (%s), want deny", d.Effect, d.Reason)
	}
}

// The same polarity bug, reachable with a policy this daemon fully understands:
// an unrankable risk is a condition it cannot evaluate either.
//
// An agent picks the risk label at store time, so `criticall` — one typo from a
// real level, and the exact string that once put an entry beyond every min_risk
// rule — is a condition the caller can create at will. Under the old polarity
// that turned the deny below into a prompt.
func TestAskOnAnUnrankableRiskDoesNotShadowADeny(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - min_risk: high
    effect: ask
    reason: a high-risk secret needs a human
  - provider: aws
    effect: deny
    reason: aws is off limits
`))
	if err != nil {
		t.Fatal(err)
	}

	unrankable := Request{Action: "assume"}.withFacts(
		Facts{}.WithLabel("aws:prod", "aws", "prod").WithClassification("Credential", "criticall"))
	if d := p.Evaluate(unrankable); d.Effect != EffectDeny {
		t.Fatalf("effect = %s (%s), want deny — a risk nobody could rank turned a deny "+
			"into a prompt", d.Effect, d.Reason)
	}

	// Rankable and over the threshold: the ask was checked, so it decides.
	rankable := Request{Action: "assume"}.withFacts(
		Facts{}.WithLabel("aws:prod", "aws", "prod").WithClassification("Credential", "critical"))
	if d := p.Evaluate(rankable); d.Effect != EffectAsk {
		t.Fatalf("effect = %s (%s), want ask — a checked min_risk rule must still fire first",
			d.Effect, d.Reason)
	}
}

// And with a server-derived fact no gate resolved. This is the /retrieve shape
// from facts.go: the gate never established a provider, so a provider-keyed rule
// is unevaluable rather than false.
func TestAskOnAnUnresolvedFactDoesNotShadowADeny(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - provider: aws
    effect: ask
    reason: approve aws
  - action: retrieve
    effect: deny
    reason: raw secret decryption is disabled — use the broker
`))
	if err != nil {
		t.Fatal(err)
	}

	// Known == 0: nothing looked up a provider for this request.
	if d := p.Evaluate(Request{Action: "retrieve"}); d.Effect != EffectDeny {
		t.Fatalf("effect = %s (%s), want deny — a provider nobody resolved must not turn "+
			"the raw-retrieve deny into a prompt", d.Effect, d.Reason)
	}

	// Once the provider IS resolved, the ask is a checked rule and wins.
	resolved := Request{Action: "retrieve"}.withFacts(
		Facts{}.WithLabel("aws:prod", "aws", "prod").WithClassification("Credential", "critical"))
	if d := p.Evaluate(resolved); d.Effect != EffectAsk {
		t.Fatalf("effect = %s (%s), want ask", d.Effect, d.Reason)
	}
}

// End to end through the engine, which is where the damage actually happened:
// the human was prompted for an operation the policy already refused, and
// clicking Allow granted it.
func TestAnUnevaluatedAskNeverPromptsForSomethingThePolicyDenies(t *testing.T) {
	path := writePolicy(t, t.TempDir(), `
rules:
  - action: assume
    lifetime: per-command
    effect: ask
    reason: written for a newer daemon
  - action: assume
    effect: deny
    reason: sessions are off
`)
	e := NewEngine(path)
	fa := &fakeApprover{allow: true}
	e.SetApprover(fa)

	err := e.Authorize(Request{Action: "assume"})
	if err == nil {
		t.Fatal("the operation was authorized: a click on a rule this daemon could not " +
			"evaluate overrode the deny below it")
	}
	if !strings.Contains(err.Error(), "sessions are off") {
		t.Errorf("denial = %v, want the deny rule's reason", err)
	}
	if fa.called != 0 {
		t.Errorf("the approver was consulted %d time(s) for an operation the policy denies "+
			"outright — prompting for a refusal trains the user to click through", fa.called)
	}
}
