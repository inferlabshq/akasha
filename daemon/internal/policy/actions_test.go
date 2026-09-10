package policy

import (
	"strings"
	"testing"
)

// The alias is what keeps an upgrade from locking a machine out.
//
// `policy init` wrote `action: assume` onto every machine that has a policy.
// The parser rejects an unknown action on BOTH paths, and a parse error denies
// everything. So a rename with no alias is not a vocabulary change; it is an
// outage delivered by the next `brew upgrade`. Both spellings must parse, on
// both paths, and evaluate identically.
func TestAssumeIsAcceptedAsAnAliasOfSession(t *testing.T) {
	for _, parse := range []struct {
		name string
		fn   func([]byte) (*Policy, error)
	}{{"strict", Parse}, {"lenient", ParseLenient}} {
		t.Run(parse.name, func(t *testing.T) {
			p, err := parse.fn([]byte("version: 1\ndefault: allow\nrules:\n  - {action: assume, effect: deny}\n"))
			if err != nil {
				t.Fatalf("an installed policy spelled `assume` no longer parses: %v", err)
			}
			for _, spelling := range []string{"session", "assume"} {
				d := p.Evaluate(Request{Action: spelling, AgentSource: Verified, ToolSource: ServerAssigned,
					known: FactProvider | FactInstance})
				if d.Effect != EffectDeny {
					t.Errorf("request spelled %q was not denied by a rule spelled `assume`: %v", spelling, d.Effect)
				}
			}
			if p.Rules[0].Action != "session" {
				t.Errorf("the rule was not normalised on read: Action=%q", p.Rules[0].Action)
			}
		})
	}
}

// Accepting an alias must not become accepting anything. The list is still a
// list, and the error still names every member of it -- generated from the
// same table, so it cannot be one verb short again.
func TestUnknownActionIsStillRefusedAndTheErrorIsComplete(t *testing.T) {
	_, err := Parse([]byte("version: 1\nrules:\n  - {action: sesion, effect: deny}\n"))
	if err == nil {
		t.Fatal("a misspelled action parsed")
	}
	for _, want := range Actions() {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the parse error does not name %q: %v", want, err)
		}
	}
}

// The deprecation report fires once per aliased rule and never for the
// canonical spelling -- it is the only signal a user gets that a file which
// works today will not parse next release.
func TestDeprecationsNameAliasedRulesOnly(t *testing.T) {
	p, err := Parse([]byte("version: 1\nrules:\n  - {action: assume, effect: deny}\n  - {action: broker, effect: allow}\n  - {action: retrieve, effect: deny}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ds := p.Deprecations()
	if len(ds) != 1 {
		t.Fatalf("want exactly one deprecation (rule 1), got %d: %v", len(ds), ds)
	}
	if !strings.Contains(ds[0], "rule 1") || !strings.Contains(ds[0], "assume") || !strings.Contains(ds[0], "session") {
		t.Errorf("the report must say which rule, which word, and which word instead: %s", ds[0])
	}
	// And it is NOT a lint problem: the rule does exactly what it looks like.
	if problems := p.Lint(); len(problems) != 0 {
		t.Errorf("an aliased rule is not a lint problem, but Lint reported: %v", problems)
	}
}

// The category lint keys on the canonical verb after normalisation, so a
// session rule keyed on category is caught whichever way it was spelled.
func TestCategoryLintSeesThroughTheAlias(t *testing.T) {
	for _, spelling := range []string{"session", "assume"} {
		p, err := Parse([]byte("version: 1\nrules:\n  - {action: " + spelling + ", category: SSN, effect: deny}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Lint()) == 0 {
			t.Errorf("a %s rule keyed on category SSN can never match and must be reported", spelling)
		}
	}
}
