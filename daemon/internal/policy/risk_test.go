package policy

import "testing"

// An unrankable risk level is "we do not know", not "the lowest level".
// Treating it as 0 meant every restrictive min_risk rule silently stopped
// applying, and a caller who stored an entry as "criticall" put it beyond the
// reach of policy entirely.

func TestRiskRankReportsUnknown(t *testing.T) {
	for _, ok := range []string{"low", "medium", "high", "critical", "CRITICAL", " high "} {
		if _, known := RiskRank(ok); !known {
			t.Errorf("RiskRank(%q): want known", ok)
		}
	}
	for _, bad := range []string{"", "criticall", "none", "HIGHEST", "1"} {
		if _, known := RiskRank(bad); known {
			t.Errorf("RiskRank(%q): want unknown", bad)
		}
		if ValidRisk(bad) {
			t.Errorf("ValidRisk(%q): want false", bad)
		}
	}
}

// The asymmetry is the whole design: unknown risk must make a restrictive rule
// APPLY while leaving a permissive one unsatisfied. A naive inversion would
// have flipped both and started granting on risk levels nobody could read.
func TestUnknownRiskFailsClosedForDeny(t *testing.T) {
	deny, err := Parse([]byte("rules:\n  - {min_risk: high, effect: deny, reason: no}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, risk := range []string{"", "criticall", "none"} {
		if d := deny.Evaluate(Request{Risk: risk}); d.Effect != EffectDeny {
			t.Errorf("deny rule, risk %q: got %s, want deny", risk, d.Effect)
		}
	}
	// A ranked risk below the threshold still falls through, as before.
	if d := deny.Evaluate(Request{Risk: "low"}); d.Effect != EffectAllow {
		t.Errorf("deny rule, risk low: got %s, want allow (below threshold)", d.Effect)
	}
}

func TestUnknownRiskDoesNotSatisfyAllow(t *testing.T) {
	allow, err := Parse([]byte("default: deny\nrules:\n  - {min_risk: high, effect: allow}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, risk := range []string{"", "criticall"} {
		if d := allow.Evaluate(Request{Risk: risk}); d.Effect != EffectDeny {
			t.Errorf("allow rule, risk %q: got %s, want deny (must not grant on an unreadable level)", risk, d.Effect)
		}
	}
	if d := allow.Evaluate(Request{Risk: "critical"}); d.Effect != EffectAllow {
		t.Errorf("allow rule, risk critical: got %s, want allow", d.Effect)
	}
}

// `ask` is restrictive too — it must behave like deny, not like allow.
func TestUnknownRiskTriggersAsk(t *testing.T) {
	p, err := Parse([]byte("rules:\n  - {min_risk: high, effect: ask}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Request{Risk: ""}); d.Effect != EffectAsk {
		t.Fatalf("ask rule, unknown risk: got %s, want ask", d.Effect)
	}
}
