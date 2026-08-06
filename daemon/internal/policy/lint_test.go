package policy

import (
	"strings"
	"testing"
)

func lintOf(t *testing.T, src string) []string {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p.Lint()
}

// A catch-all above anything else makes everything below it dead. This is the
// shape that turns a careful-looking lockdown into a no-op.
func TestLintFlagsCatchAllAboveRules(t *testing.T) {
	got := lintOf(t, `
rules:
  - {effect: allow}
  - {action: retrieve, effect: deny, reason: never reached}
`)
	if len(got) == 0 {
		t.Fatal("a catch-all allow above a deny must be flagged")
	}
	if !strings.Contains(got[0], "unreachable") {
		t.Errorf("warning should say unreachable, got %q", got[0])
	}
}

// A broader rule shadows a narrower one with the same matchers.
func TestLintFlagsSubsumedRule(t *testing.T) {
	got := lintOf(t, `
rules:
  - {action: retrieve, effect: allow}
  - {action: retrieve, min_risk: high, effect: deny, reason: never reached}
`)
	if len(got) != 1 {
		t.Fatalf("want 1 warning, got %d: %v", len(got), got)
	}
}

// The common correct shape — specific exception above a blanket rule — must NOT
// be flagged, or the warning becomes noise people learn to ignore.
func TestLintAllowsSpecificAboveGeneral(t *testing.T) {
	got := lintOf(t, `
rules:
  - {action: retrieve, agent: claude, effect: allow}
  - {action: retrieve, effect: deny}
`)
	if len(got) != 0 {
		t.Fatalf("specific-above-general is correct and must not warn: %v", got)
	}
}

// Same effect twice is redundant, not dangerous — no warning.
func TestLintIgnoresSameEffect(t *testing.T) {
	got := lintOf(t, `
rules:
  - {action: retrieve, effect: deny}
  - {action: retrieve, min_risk: high, effect: deny}
`)
	if len(got) != 0 {
		t.Fatalf("same-effect shadowing changes nothing observable: %v", got)
	}
}

// A higher earlier threshold does not cover a lower later one.
func TestLintMinRiskDirection(t *testing.T) {
	if got := lintOf(t, `
rules:
  - {action: retrieve, min_risk: critical, effect: allow}
  - {action: retrieve, min_risk: low, effect: deny}
`); len(got) != 0 {
		t.Fatalf("critical does not subsume low: %v", got)
	}
	if got := lintOf(t, `
rules:
  - {action: retrieve, min_risk: low, effect: allow}
  - {action: retrieve, min_risk: critical, effect: deny}
`); len(got) != 1 {
		t.Fatalf("low DOES subsume critical, want 1 warning, got %v", got)
	}
}

// assume/broker are always evaluated as Credential, so a category rule on those
// paths can never fire — a rule that looks like a gate and is not one.
func TestLintFlagsImpossibleCategoryOnAssume(t *testing.T) {
	got := lintOf(t, `
rules:
  - {action: assume, category: SSN, effect: deny}
`)
	if len(got) != 1 || !strings.Contains(got[0], "never match") {
		t.Fatalf("want an impossible-category warning, got %v", got)
	}

	// category: Credential is the one that does match.
	if got := lintOf(t, `
rules:
  - {action: assume, category: Credential, effect: deny}
`); len(got) != 0 {
		t.Fatalf("category Credential is valid on assume: %v", got)
	}
}

// The shipped starter policy must lint clean, or the first thing a user does
// produces a warning.
func TestStarterPolicyLintsClean(t *testing.T) {
	// Mirrors the rules in cmd/akasha starterPolicy.
	got := lintOf(t, `
default: allow
rules:
  - {action: retrieve, effect: deny, reason: raw secret decryption is disabled}
  - {action: grant, min_risk: high, effect: ask}
  - {action: grant, effect: allow}
`)
	if len(got) != 0 {
		t.Fatalf("starter policy should lint clean, got: %v", got)
	}
}
