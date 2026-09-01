package policy

import (
	"strings"
	"testing"
)

func req(action, provider string) Request {
	return Request{
		Action: action, Provider: provider,
		Category: "Credential", Risk: "critical",
		AgentSource: Verified, ToolSource: ServerAssigned,
		// A real gate that names a provider also declares that it resolved
		// one; without this the request models a gate that never looked, which
		// fails closed by design (facts.go).
		Known: FactProvider | FactInstance,
	}
}

// The property that makes every future matcher safe to add.
//
// Before this, a new key was a one-way door: strict parsing, no lenient path,
// no min_daemon gate, and a parse error makes Authorize deny EVERY operation.
// A user who adopted a new matcher and then ran an older daemon did not get
// degraded security, they got a total outage.
func TestUnknownMatcherFailsClosedInsteadOfLockingTheMachine(t *testing.T) {
	doc := `
rules:
  - action: assume
    lifetime: per-command
    effect: deny
    reason: written for a newer daemon
`
	p, err := ParseLenient([]byte(doc))
	if err != nil {
		t.Fatalf("a rule with one unrecognized matcher must not fail the whole file: %v", err)
	}
	if got := p.Rules[0].UnknownMatchers(); len(got) != 1 || got[0] != "lifetime" {
		t.Fatalf("unknown matchers = %v, want [lifetime]", got)
	}

	// A deny it cannot fully evaluate still denies: the unevaluated condition
	// could only have narrowed the rule, so ignoring it is the restrictive read.
	if d := p.Evaluate(req("assume", "aws")); d.Effect != EffectDeny {
		t.Errorf("effect = %s, want deny — an older daemon must still honour the restriction", d.Effect)
	}
}

// …and the other half of the asymmetry: it may narrow, never grant.
func TestUnknownMatcherCannotSatisfyAnAllow(t *testing.T) {
	doc := `
default: deny
rules:
  - action: assume
    lifetime: per-command
    effect: allow
    reason: only meant to allow the per-command case
`
	p, err := ParseLenient([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	// The rule's author meant "allow, but only when lifetime is per-command".
	// A daemon that cannot check that condition must not grant on the rest.
	if d := p.Evaluate(req("assume", "aws")); d.Effect != EffectDeny {
		t.Errorf("effect = %s, want the default deny — an allow was granted on a condition "+
			"this daemon never evaluated", d.Effect)
	}
}

// A key at the DOCUMENT level stays fatal. A document key defines what the file
// means, and a policy engine may not guess at a document whose meaning is
// unknown. This is the line the template loader draws too.
func TestUnknownDocumentKeyIsStillFatal(t *testing.T) {
	_, err := ParseLenient([]byte("mode: permissive\nrules: []\n"))
	if err == nil {
		t.Fatal("an unknown top-level key was accepted")
	}
	if !strings.Contains(err.Error(), "top-level") {
		t.Errorf("the refusal should say why a document key is different: %v", err)
	}
}

// Malformed is not the same as newer, and must not be forgiven.
func TestMalformedPolicyIsStillFatal(t *testing.T) {
	for name, doc := range map[string]string{
		"not yaml":     "rules: [{effect: allow}\n",
		"bad effect":   "rules: [{effect: block}]",
		"bad risk":     "rules: [{effect: deny, min_risk: severe}]",
		"bad action":   "rules: [{effect: deny, action: read}]",
		"bad default":  "default: ask",
		"rules scalar": "rules: 3",
	} {
		if _, err := ParseLenient([]byte(doc)); err == nil {
			t.Errorf("%s: accepted a malformed policy", name)
		}
	}
}

// The authoring path stays strict, or a typo becomes a rule that silently does
// something other than what its author wrote.
func TestStrictParseStillRejectsAnUnknownMatcher(t *testing.T) {
	doc := "rules: [{effect: allow, agnet: claude}]"
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("`akasha policy validate` would no longer catch a misspelled matcher")
	}
	if _, err := ParseLenient([]byte(doc)); err != nil {
		t.Fatalf("the daemon should tolerate it rather than deny everything: %v", err)
	}
}

// Only the rules that carry an unknown key are affected; the rest of the file
// keeps working exactly as written.
func TestOnlyTheAffectedRuleIsDowngraded(t *testing.T) {
	p, err := ParseLenient([]byte(`
default: deny
rules:
  - action: assume
    provider: gcp
    lifetime: per-command
    effect: allow
  - action: assume
    provider: aws
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(req("assume", "gcp")); d.Effect != EffectDeny {
		t.Errorf("gcp: effect = %s, want deny (its rule could not be fully evaluated)", d.Effect)
	}
	if d := p.Evaluate(req("assume", "aws")); d.Effect != EffectAllow {
		t.Errorf("aws: effect = %s, want allow — a clean rule must be unaffected by a "+
			"neighbour the daemon did not understand", d.Effect)
	}
}

// A rule that constrains only `sandbox:` is not a catch-all, and neither is one
// whose only other matcher this daemon cannot read. Reporting either as "no
// matchers" makes lint call every rule below it unreachable — advice that,
// followed, deletes working rules.
func TestLintDoesNotTreatSandboxOrUnknownAsNoMatchers(t *testing.T) {
	yes := true
	if isCatchAll(Rule{Sandbox: &yes, Effect: EffectDeny}) {
		t.Error("a sandbox-only rule was reported as constraining nothing")
	}
	if isCatchAll(Rule{unknown: []string{"lifetime"}, Effect: EffectDeny}) {
		t.Error("a rule with an unevaluated matcher was reported as constraining nothing")
	}
	if !isCatchAll(Rule{Effect: EffectDeny}) {
		t.Error("a genuinely unconstrained rule is no longer detected")
	}

	// And it must appear in the description rather than vanishing from it.
	if d := describe(Rule{Sandbox: &yes, Effect: EffectDeny}); !strings.Contains(d, "sandbox") {
		t.Errorf("describe() omits the sandbox matcher: %q", d)
	}
	if d := describe(Rule{unknown: []string{"lifetime"}, Effect: EffectDeny}); !strings.Contains(d, "lifetime") {
		t.Errorf("describe() omits the unevaluated matcher: %q", d)
	}
}

// The matcher that expresses the owner's sentence — "agents broker production,
// humans may assume it" — on an input a caller cannot forge.
func TestCallerMatcher(t *testing.T) {
	p, err := Parse([]byte(`
default: deny
rules:
  - action: assume
    caller: human
    effect: allow
  - action: broker
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}

	human := req("assume", "aws")
	human.Human = true
	if d := p.Evaluate(human); d.Effect != EffectAllow {
		t.Errorf("human assume = %s, want allow", d.Effect)
	}

	agent := req("assume", "aws")
	if d := p.Evaluate(agent); d.Effect != EffectDeny {
		t.Errorf("agent assume = %s, want the default deny", d.Effect)
	}
	if d := p.Evaluate(req("broker", "aws")); d.Effect != EffectAllow {
		t.Errorf("agent broker = %s, want allow — per-operation use is the routine path", d.Effect)
	}
}

// A typo must not silently become "any caller".
func TestCallerMatcherRejectsAnUnknownValue(t *testing.T) {
	_, err := Parse([]byte("rules: [{effect: deny, caller: robot}]"))
	if err == nil {
		t.Fatal("caller: robot was accepted; the rule would have matched everyone")
	}
	if !strings.Contains(err.Error(), "caller") {
		t.Errorf("the refusal should name the field: %v", err)
	}
}
