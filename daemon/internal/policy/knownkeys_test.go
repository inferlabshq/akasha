package policy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// knownRuleKeys is hand-maintained, and policy.go says why it is not derived by
// reflection: a typo in a struct tag would silently widen what the daemon
// claims to understand. That argument holds. What it leaves open is drift, and
// one direction of that drift is FAIL-OPEN.
//
// Put a key in the map that no Rule field decodes — a matcher added to the
// vocabulary before, or instead of, the field that would evaluate it — and:
//
//  1. the strict decoder rejects any document using it (no such field),
//  2. so parse() falls through to parseTolerant,
//  3. which asks knownRuleKeys whether the key is understood and is told yes,
//  4. so the key never lands in Rule.unknown,
//  5. and matches() lets an `allow` rule fire with its author's condition
//     silently dropped.
//
// That inverts the one property the lenient path exists to guarantee — an
// unevaluated condition may NARROW, never GRANT — in the file where fail-open
// is least acceptable. These tests are what keeps the vocabulary in a human's
// hands without letting it drift away from the struct that implements it.

// nonMatcherRuleKeys are the keys a rule carries that are not conditions at
// all: they are its outcome. They are listed here because they must be in
// knownRuleKeys anyway and the reason is easy to lose — parseTolerant walks
// EVERY key of the rule mapping, not just the matchers, so an absent "effect"
// would mark every rule in a tolerantly parsed document as carrying an
// unevaluated matcher and stop every `allow` in the file from firing.
//
// Naming them makes the split explicit, rather than a case the guard skips
// without saying so, and lets a complaint about one of them state the much
// larger blast radius.
var nonMatcherRuleKeys = map[string]string{
	"effect": "the decision the rule returns",
	"reason": "the explanation handed to the human",
}

// ruleDecodeKeys maps the YAML key each Rule field is decoded from to that
// field's Go name.
//
// It reads what the DECODER will do, not what the tags say: an exported field
// with no yaml tag is still decoded, from its lowercased name, so a field added
// without a tag is a live key and has to be checked like any other.
func ruleDecodeKeys(t *testing.T) map[string]string {
	t.Helper()

	keys := make(map[string]string)
	rt := reflect.TypeOf(Rule{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue // Rule.unknown is engine bookkeeping; the decoder never sees it.
		}
		tag := f.Tag.Get("yaml")
		name, opts, _ := strings.Cut(tag, ",")
		if strings.Contains(","+opts+",", ",inline,") {
			t.Fatalf("Rule.%s is inline, so it flattens its own keys into the rule "+
				"mapping where this guard cannot see them: teach the guard to walk "+
				"into it before shipping the field", f.Name)
		}
		switch name {
		case "-":
			continue
		case "":
			name = strings.ToLower(f.Name)
		}
		if prev, dup := keys[name]; dup {
			t.Fatalf("Rule.%s and Rule.%s both decode from %q; the vocabulary cannot "+
				"describe which one a document means", prev, f.Name, name)
		}
		keys[name] = f.Name
	}
	return keys
}

// checkKnownRuleKeys returns one complaint per disagreement between a
// vocabulary map and the fields Rule actually decodes.
//
// Both sides are arguments so the guard can be pointed at a doctored map and
// shown to fire — a guard nobody has watched fail is a guard nobody knows
// works.
func checkKnownRuleKeys(known map[string]bool, fields map[string]string) []string {
	var out []string

	// A false entry is not "known": parseTolerant tests `!knownRuleKeys[k]`,
	// which reads absent and false the same way. Treat them the same here or
	// the guard would bless a key the parser still rejects.
	for key, claimed := range known {
		if !claimed {
			continue
		}
		if _, ok := fields[key]; ok {
			continue
		}
		out = append(out, fmt.Sprintf(
			"knownRuleKeys lists %q but no Rule field decodes it. This is the FAIL-OPEN "+
				"direction: the strict decoder rejects any document using %q, parse() falls "+
				"through to parseTolerant, which asks this map and is told the key is "+
				"understood — so it never reaches Rule.unknown, and an `allow` rule carrying "+
				"%q GRANTS with the condition its author wrote silently dropped. Add the field "+
				"to Rule (tagged yaml:%q) in the same change as this map entry, or remove the "+
				"entry until the field lands.",
			key, key, key, key))
	}

	for key, field := range fields {
		if known[key] {
			continue
		}
		if why, outcome := nonMatcherRuleKeys[key]; outcome {
			out = append(out, fmt.Sprintf(
				"knownRuleKeys is missing %q (Rule.%s — %s). Every rule in every file carries "+
					"it, so on the tolerant path EVERY rule would be recorded as carrying a "+
					"matcher this daemon cannot evaluate and EVERY `allow` in the file would "+
					"stop firing. Add %q: true to knownRuleKeys.",
				key, field, why, key))
			continue
		}
		out = append(out, fmt.Sprintf(
			"knownRuleKeys is missing %q (Rule.%s). Fail-closed, but still wrong: as soon as a "+
				"document also carries a key from a newer daemon it takes the tolerant path, "+
				"where %q is reported as unevaluated — so an `allow` written in this daemon's "+
				"own vocabulary stops firing and lint renders it as `%s: ?`. Add %q: true to "+
				"knownRuleKeys.",
			key, field, key, key, key))
	}

	// A classification that outlives its field stops describing anything.
	for key := range nonMatcherRuleKeys {
		if _, ok := fields[key]; !ok {
			out = append(out, fmt.Sprintf(
				"nonMatcherRuleKeys names %q, which Rule no longer decodes: re-file the entry "+
					"under the field's new name or delete it, so the matcher/outcome split "+
					"keeps meaning something.", key))
		}
	}

	sort.Strings(out)
	return out
}

// The guard itself: the vocabulary the daemon advertises and the struct that
// implements it must agree in BOTH directions.
func TestKnownRuleKeysAgreesWithTheRuleStruct(t *testing.T) {
	for _, problem := range checkKnownRuleKeys(knownRuleKeys, ruleDecodeKeys(t)) {
		t.Error(problem)
	}
}

// …and the guard is only worth having if it fires. Each subtest is a drift a
// reviewer could plausibly wave through.
func TestTheGuardFiresOnDriftInEitherDirection(t *testing.T) {
	fields := ruleDecodeKeys(t)

	// Each case starts from a vocabulary that agrees with the struct by
	// construction, NOT from knownRuleKeys: whether the shipped map is healthy
	// is the other test's question, and a real drift must not turn these into
	// a wall of unrelated noise.
	doctor := func(add string, remove string) map[string]bool {
		m := make(map[string]bool, len(fields)+1)
		for k := range fields {
			m[k] = true
		}
		if add != "" {
			m[add] = true
		}
		if remove != "" {
			delete(m, remove)
		}
		return m
	}

	only := func(t *testing.T, problems []string, key string) string {
		t.Helper()
		if len(problems) != 1 {
			t.Fatalf("want exactly one complaint about %q, got %d: %v", key, len(problems), problems)
		}
		if !strings.Contains(problems[0], `"`+key+`"`) {
			t.Fatalf("the complaint does not name the offending key %q: %s", key, problems[0])
		}
		return problems[0]
	}

	t.Run("key with no field is called out as fail-open", func(t *testing.T) {
		got := only(t, checkKnownRuleKeys(doctor("lifetime", ""), fields), "lifetime")
		if !strings.Contains(got, "FAIL-OPEN") || !strings.Contains(got, "Add the field to Rule") {
			t.Errorf("a fail-open complaint must say so and say what to do: %s", got)
		}
	})

	t.Run("field with no key", func(t *testing.T) {
		got := only(t, checkKnownRuleKeys(doctor("", "provider"), fields), "provider")
		if !strings.Contains(got, "Add \"provider\": true") {
			t.Errorf("the complaint does not say what to do: %s", got)
		}
	})

	t.Run("a false entry counts as missing, the way the parser reads it", func(t *testing.T) {
		m := doctor("", "")
		m["provider"] = false
		only(t, checkKnownRuleKeys(m, fields), "provider")
	})

	t.Run("a missing outcome key names the larger blast radius", func(t *testing.T) {
		got := only(t, checkKnownRuleKeys(doctor("", "effect"), fields), "effect")
		if !strings.Contains(got, "EVERY `allow` in the file") {
			t.Errorf("dropping `effect` breaks every rule in the file; the complaint should "+
				"say that rather than read like one more missing matcher: %s", got)
		}
	})

	t.Run("a classification left behind by a renamed field", func(t *testing.T) {
		fewer := make(map[string]string, len(fields))
		for k, v := range fields {
			fewer[k] = v
		}
		delete(fewer, "reason")
		// Drop it from the vocabulary too, so the only complaint under test is
		// the stale classification rather than the missing-key one.
		problems := checkKnownRuleKeys(doctor("", "reason"), fewer)
		got := only(t, problems, "reason")
		if !strings.Contains(got, "nonMatcherRuleKeys") {
			t.Errorf("the complaint should point at the stale classification: %s", got)
		}
	})
}

// The hazard itself, executed rather than argued, so nobody deletes the guard
// above as paranoia.
//
// `lifetime:` is the real near-miss: it was proposed as a rule key and rejected
// (the two lifetime modes ARE the assume/broker verbs), which is exactly how an
// entry ends up in the vocabulary while the field it needs is still being
// argued about.
//
// This pins the CURRENT hazard, not a behaviour worth keeping. If parseTolerant
// ever learns to catch this itself, this test should fail — rewrite it then,
// and keep the guard.
func TestAVocabularyKeyWithNoFieldGrantsOnAConditionNeverEvaluated(t *testing.T) {
	const key = "lifetime"
	if field, ok := ruleDecodeKeys(t)[key]; ok {
		t.Fatalf("Rule.%s now decodes %q, so this test no longer models the drift it "+
			"describes: pick a key the struct does not have", field, key)
	}

	// Package-level state: this package's tests are not parallel, and the
	// parser reads the map directly, so there is no narrower seam. Restore
	// whatever was there rather than deleting, so that running this while the
	// map is ALREADY drifted cannot quietly repair it for the tests that follow.
	prior, had := knownRuleKeys[key]
	knownRuleKeys[key] = true
	defer func() {
		if had {
			knownRuleKeys[key] = prior
			return
		}
		delete(knownRuleKeys, key)
	}()

	p, err := ParseLenient([]byte(`
default: deny
rules:
  - action: assume
    lifetime: per-command
    effect: allow
    reason: only meant to allow the per-command case
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Rules[0].UnknownMatchers(); len(got) != 0 {
		t.Fatalf("unknown matchers = %v: the vocabulary no longer hides a key with no "+
			"field, so this test needs rewriting — the guard is the part that matters", got)
	}
	if d := p.Evaluate(req("assume", "aws")); d.Effect != EffectAllow {
		t.Fatalf("effect = %s: the fail-open did not reproduce. If the parser now "+
			"cross-checks the struct, delete this test and keep the guard", d.Effect)
	}
	// The rule's author wrote "allow, but only for per-command lifetimes". The
	// daemon just granted without ever looking at that clause — and the guard
	// is the only thing standing between that map entry and a release.
	if len(checkKnownRuleKeys(knownRuleKeys, ruleDecodeKeys(t))) == 0 {
		t.Error("the guard did not report the drift that produced this grant")
	}
}
