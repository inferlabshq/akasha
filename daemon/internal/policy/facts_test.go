package policy

import (
	"errors"
	"testing"
)

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
		Action: "retrieve", category: "SSN", risk: "critical",
		AgentSource: Verified, ToolSource: ServerAssigned,
		known: FactProvider | FactInstance,
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
	resolved := Request{Action: "assume", known: FactBrokerable}
	if !allow.matches(resolved) {
		t.Error("once the template is consulted, an allow may grant")
	}
}

// Provider and Instance are SEPARATE bits, even though every gate in the tree
// today resolves them together by splitting one label.
//
// The temptation is to collapse them into one "label resolved" flag on the
// observation that no caller sets one without the other. That forecloses the
// case facts.go reserves: a gate that knows which provider it is talking to but
// not which profile — a source-backed provider enumerating instances, say — has
// to be able to say exactly that, or `instance:` rules silently start granting
// on a value nobody looked up.
func TestProviderAndInstanceAreSeparateFacts(t *testing.T) {
	// The provider was resolved; the instance was not.
	half := Request{Action: "assume"}.withFacts(
		Facts{provider: "aws", known: FactProvider})

	allowProvider := Rule{Provider: "aws", Effect: EffectAllow}
	if !allowProvider.matches(half) {
		t.Error("an allow keyed on the provider must grant once the provider IS resolved, " +
			"whatever happened to the instance")
	}
	allowInstance := Rule{Instance: "prod", Effect: EffectAllow}
	if allowInstance.matches(half) {
		t.Error("an allow keyed on the instance must NOT grant while the instance is unresolved — " +
			"that is the half this bit exists to keep separate")
	}
	denyInstance := Rule{Instance: "prod", Effect: EffectDeny}
	if !denyInstance.matches(half) {
		t.Error("a deny keyed on the instance must still bind when the instance is unresolved")
	}
}

// fixedFacts is a FactResolver that hands back exactly the views a test names.
//
// The engine's own tests use it rather than the daemon's real derivation on
// purpose: the matcher has a specification and the derivation has a
// specification, and routing one through the other means a regression in either
// produces the same red. Server-side tests cover the real one.
type fixedFacts []Facts

func (f fixedFacts) FactsFor(Subject) ([]Facts, error) { return f, nil }

// The zero Subject is refused, not treated as "names no provider".
//
// Vault-wide is resolved-and-empty, which a provider-scoped deny rule does not
// match — so if that were the zero value, a gate that forgot to say what it acts
// on would get the PERMISSIVE reading. That is the original bug with a new
// spelling, and it is the one thing the zero value must not do.
func TestZeroSubjectIsRefusedNotTreatedAsVaultWide(t *testing.T) {
	e := NewEngine(writePolicy(t, t.TempDir(), "default: allow\nrules: []\n"))
	e.SetFactResolver(refusingResolver{})
	if err := e.Authorize(Request{Action: "retrieve"}); err == nil {
		t.Fatal("a request whose subject was never named must be refused, even under `default: allow` — " +
			"the alternative is that forgetting to name a subject reads as `this names no provider`, " +
			"which is exactly the answer a provider rule cannot see")
	}
}

// refusingResolver models the daemon's derivation only in the one respect this
// test is about: SubjectUnset is not a thing it can answer.
type refusingResolver struct{}

func (refusingResolver) FactsFor(sub Subject) ([]Facts, error) {
	if sub.Kind() == SubjectUnset {
		return nil, errUnnamedSubject
	}
	return []Facts{{}}, nil
}

var errUnnamedSubject = errors.New("this gate did not say what it acts on")

// A resolver that returns NO view must not be read as "nothing to check".
//
// "Every view must pass" is vacuously true over an empty set, so zero views
// skips the gate as completely as never calling Authorize at all — and zero
// views is one `for range` over an empty slice away, which is exactly how a
// label-less token would have produced them.
func TestNoViewsIsARefusalNotAPass(t *testing.T) {
	e := NewEngine(writePolicy(t, t.TempDir(), "default: allow\nrules: []\n"))
	e.SetFactResolver(fixedFacts{})
	if err := e.Authorize(Request{Action: "retrieve", Subject: OfToken("tok")}); err == nil {
		t.Fatal("an operation the daemon produced no view of must be refused, not allowed by " +
			"an empty loop")
	}
}

// EVERY view has to pass, not the first one and not any one.
//
// This is the alias union, expressed against the engine rather than the vault: a
// secret reachable under two names is governed by both names' rules, or the
// looser name launders the stricter one. The loop used to be hand-written at
// each gate, and the gates that never wrote it were the bypass.
func TestEveryViewMustPass(t *testing.T) {
	e := NewEngine(writePolicy(t, t.TempDir(), `
default: allow
rules:
  - provider: aws
    effect: deny
    reason: aws is off limits
`))
	// The caller asked under a name no rule mentions; the same secret also
	// answers to an aws name.
	e.SetFactResolver(fixedFacts{
		Facts{}.WithLabel("zz:1", "zz", "1"),
		Facts{}.WithLabel("aws:prod", "aws", "prod").AsAlias(),
	})
	err := e.Authorize(Request{Action: "assume", Subject: OfCredential("zz:1", "tok", "Credential", "critical")})
	if err == nil {
		t.Fatal("a secret that also answers to a denied name must be denied under either name")
	}
	// And the refusal has to say WHICH name refused, or a denial on a name the
	// caller never typed is unexplainable.
	var d *Denial
	if !errors.As(err, &d) {
		t.Fatalf("a rule denial must be a *Denial so the gate can attribute it: %T", err)
	}
	if d.Request.Label() != "aws:prod" || !d.Request.IsAlias() {
		t.Errorf("Denial names %q (alias=%v), want the aws:prod alias — without this the "+
			"\"also bound to\" message and the DENIED audit event lose the view that failed",
			d.Request.Label(), d.Request.IsAlias())
	}
}

// An engine nobody wired a resolver into establishes nothing, which means
// restrictive rules still bind and permissive ones cannot.
func TestEngineWithoutAResolverDegradesTowardRefusal(t *testing.T) {
	deny := NewEngine(writePolicy(t, t.TempDir(), "default: allow\nrules: [{provider: aws, effect: deny}]\n"))
	if err := deny.Authorize(Request{Action: "assume", Subject: OfToken("tok")}); err == nil {
		t.Error("with no resolver a provider deny must still bind: the condition was not evaluated, " +
			"and an unevaluated condition could only have narrowed the rule further")
	}
	allow := NewEngine(writePolicy(t, t.TempDir(), "default: deny\nrules: [{provider: aws, effect: allow}]\n"))
	if err := allow.Authorize(Request{Action: "assume", Subject: OfToken("tok")}); err == nil {
		t.Error("with no resolver a provider allow must NOT grant: granting on a condition nobody " +
			"evaluated is the failure this package exists to stop")
	}
}
