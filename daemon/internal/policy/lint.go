package policy

import (
	"fmt"
	"strconv"
)

// Lint reports rules that will not do what they appear to do.
//
// Evaluation is first-match, so a policy that READS like a lockdown may not be
// one: a broad rule above a narrow one silently swallows it, and nothing in
// Parse notices because each rule is individually valid. The failure mode is
// the dangerous direction — you believe you are protected and the file agrees
// with you.
//
// These are warnings, never errors. A shadowed rule is usually a mistake but is
// occasionally deliberate (a permissive exception above a blanket deny is the
// normal shape of an allow-list), so this reports and lets the human decide.
func (p *Policy) Lint() []string {
	var out []string

	for i, r := range p.Rules {
		// A rule with no matchers at all matches every request, so nothing
		// after it can ever fire.
		if isCatchAll(r) && i < len(p.Rules)-1 {
			out = append(out, fmt.Sprintf(
				"rule %d matches everything (no matchers), so rules %d-%d below it are unreachable",
				i+1, i+2, len(p.Rules)))
			continue
		}
		for j := i + 1; j < len(p.Rules); j++ {
			if subsumes(r, p.Rules[j]) {
				out = append(out, fmt.Sprintf(
					"rule %d (%s) is unreachable: rule %d already matches everything it does",
					j+1, describe(p.Rules[j]), i+1))
			}
		}
	}

	// An `assume`/`broker` rule keyed on category can never match: those paths
	// are always evaluated as Credential/critical regardless of how the
	// underlying entries were classified.
	for i, r := range p.Rules {
		if (r.Action == "assume" || r.Action == "broker") && r.Category != "" &&
			!globMatch(r.Category, "Credential") {
			out = append(out, fmt.Sprintf(
				"rule %d can never match: %s is always evaluated as category Credential, but this rule requires category %q",
				i+1, r.Action, r.Category))
		}
	}

	return out
}

// isCatchAll reports whether a rule constrains nothing.
// isCatchAll reports whether a rule constrains nothing, and so shadows
// everything after it.
//
// Sandbox and the unknown matchers are counted here, not just the string
// fields. Omitting Sandbox was a live bug: a rule matching only `sandbox: true`
// was reported as "no matchers", so lint called every rule below it unreachable
// when none of them were — advice that, followed, deletes working rules.
func isCatchAll(r Rule) bool {
	return r.Action == "" && r.Agent == "" && r.Tool == "" && r.Provider == "" &&
		r.Instance == "" && r.Category == "" && r.MinRisk == "" &&
		r.Sandbox == nil && r.Caller == "" && len(r.unknown) == 0
}

// subsumes reports whether every request matching `later` also matches
// `earlier`, which makes `later` unreachable under first-match evaluation.
//
// Deliberately conservative: it only claims subsumption for matchers that are
// equal or where the earlier one is an unconstrained wildcard. Glob-vs-glob
// containment ("prod-*" covers "prod-db") is not attempted — a lint that cries
// wolf gets ignored, and being quiet about a real shadow is cheaper than being
// wrong about a fine one.
func subsumes(earlier, later Rule) bool {
	if earlier.Effect == later.Effect {
		// Same outcome — shadowing changes nothing observable.
		return false
	}
	// A rule carrying a matcher this daemon cannot evaluate is one whose reach
	// is unknown, so no claim about what it shadows is available. Saying
	// nothing beats a confident warning derived from half the rule.
	if len(earlier.unknown) > 0 || len(later.unknown) > 0 {
		return false
	}
	// Likewise a sandbox constraint: it is an exact-equality matcher with no
	// string form, so the pair walk below cannot see it and would over-report.
	if earlier.Sandbox != nil && (later.Sandbox == nil || *earlier.Sandbox != *later.Sandbox) {
		return false
	}
	pairs := [][2]string{
		{earlier.Action, later.Action},
		{earlier.Agent, later.Agent},
		{earlier.Tool, later.Tool},
		{earlier.Provider, later.Provider},
		{earlier.Instance, later.Instance},
		{earlier.Category, later.Category},
		{earlier.Caller, later.Caller},
	}
	for _, pr := range pairs {
		if pr[0] == "" {
			continue // earlier is unconstrained here: covers anything later says
		}
		if pr[0] != pr[1] {
			return false
		}
	}
	// min_risk: earlier covers later only if its threshold is no higher.
	if earlier.MinRisk != "" {
		if later.MinRisk == "" {
			return false
		}
		e, _ := RiskRank(earlier.MinRisk)
		l, _ := RiskRank(later.MinRisk)
		if e > l {
			return false
		}
	}
	return true
}

// describe renders a rule compactly for a warning line.
func describe(r Rule) string {
	s := ""
	add := func(k, v string) {
		if v != "" {
			if s != "" {
				s += " "
			}
			s += k + ": " + v
		}
	}
	add("action", r.Action)
	add("agent", r.Agent)
	add("tool", r.Tool)
	add("provider", r.Provider)
	add("instance", r.Instance)
	add("category", r.Category)
	add("min_risk", r.MinRisk)
	add("caller", r.Caller)
	if r.Sandbox != nil {
		add("sandbox", strconv.FormatBool(*r.Sandbox))
	}
	for _, k := range r.unknown {
		add(k, "?")
	}
	if s == "" {
		s = "no matchers"
	}
	return s + " -> " + string(r.Effect)
}
