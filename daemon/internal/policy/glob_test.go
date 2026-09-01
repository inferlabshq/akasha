package policy

import "testing"

// TestGlobCrossesSeparator is the regression for a rule that silently did
// nothing.
//
// globMatch used filepath.Match, whose "*" matches only non-separator runs
// because it is built for paths. But policy matchers hold identifiers, and
// escrow instances ARE absolute paths — so the gating pattern documented in
// POLICY.md never fired, and "approve every escrow read" fell through to the
// default.
func TestGlobCrossesSeparator(t *testing.T) {
	const instance = "/Users/me/.aws/credentials"

	for _, pattern := range []string{
		"*",
		"*credentials",
		"/Users/me/*",
		"/Users/*/.aws/credentials",
		"*/.aws/*",
	} {
		if !globMatch(pattern, instance) {
			t.Errorf("globMatch(%q, %q) = false, want true (a '*' must cross '/')", pattern, instance)
		}
	}

	// Still discriminating — crossing separators must not mean matching all.
	for _, pattern := range []string{
		"/etc/*",
		"*.pem",
		"/Users/other/*",
	} {
		if globMatch(pattern, instance) {
			t.Errorf("globMatch(%q, %q) = true, want false", pattern, instance)
		}
	}
}

// TestEscrowGatingRuleApplies exercises the documented escrow rule end to end
// through the engine, not just the matcher.
func TestEscrowGatingRuleApplies(t *testing.T) {
	p, err := Parse([]byte(`
rules:
  - action: assume
    provider: escrow
    instance: "*"
    effect: deny
    reason: escrowed originals need approval
`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{
		Action:   "assume",
		provider: "escrow",
		instance: "/Users/me/.ssh/id_ed25519",
	})
	if d.Effect != EffectDeny {
		t.Fatalf("escrow rule did not apply: got %s, want deny", d.Effect)
	}
}

func TestGlobSyntax(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"", "anything", true},     // empty pattern is a wildcard
		{"*", "", true},            // and '*' matches empty
		{"aws", "aws", true},       // literal
		{"aws", "aws-prod", false}, // literal is anchored at both ends
		{"AWS", "aws", true},       // case-insensitive both ways
		{"aws", "AWS", true},       //
		{"vscode*", "vscode-insiders", true},
		{"*prod", "aws-prod", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"?", "a", true},
		{"?", "ab", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"**", "anything", true}, // consecutive stars are harmless

		// filepath.Match treated these as syntax; they are now literals, which
		// means no pattern can be "malformed" and silently disable its rule.
		{"prod-[", "prod-[", true},
		{"prod-[", "prod-x", false},
		{"a\\b", "a\\b", true},
		{"[abc]", "a", false}, // NOT a character class
		{"[abc]", "[abc]", true},

		// '?' consumes one character, not one byte.
		{"caf?", "café", true},
		{"?", "é", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.value); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

// TestGlobBacktracking guards the matcher's one subtle bit: a '*' that
// initially consumes too much has to give characters back.
func TestGlobBacktracking(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*aa", "aaaa", true},
		{"*ab", "aaab", true},
		{"a*a*a", "aaaa", true},
		{"*x*y*z", "1x2y3z", true},
		{"*x*y*z", "1x2z3y", false},
		{"*/.aws/*", "/a/b/c/.aws/credentials", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.value); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}
