package policy

// A FACT is a server-derived condition the daemon either established for this
// request or did not. The distinction has to be explicit, because for every one
// of them the zero value is also a legitimate answer: Provider "" is both "this
// entry carries no provider label" and "this gate never looked", and Brokerable
// false is both "no per-operation route exists" and "nobody asked the template".
//
// Conflating those two is how a policy fails OPEN. Shipped, and reproduced with
// a control before this existed: with one rule `{provider: aws, effect: deny}`
// and one aws-labelled secret, /assume answered 403 and /retrieve answered 200
// with the plaintext — because the /retrieve gate never set Provider, so
// globMatch("aws", "") was false, the rule did not match, and the request fell
// through to the default. The rule bound on the door that hands out no
// plaintext and missed the one that does, which is the exact inverse of the
// axis this product is built on.
//
// The engine already had the right answer for two facts it could not read —
// Category and MinRisk both fail CLOSED in both directions (a deny/ask rule
// matches, an allow rule does not). Those two are self-describing: an
// unrankable risk is visibly unrankable. Provider, Instance and Brokerable are
// not, so they need the gate to say whether it looked. This is that.
//
// The cost of forgetting is now the safe direction. A new gate that populates
// nothing gets Known == 0, so every provider/instance/brokerable rule treats it
// as unevaluable: restrictive rules still bind, permissive ones cannot.
type FactSet uint16

const (
	// FactProvider — Provider was resolved for this request (possibly to "",
	// meaning the entry genuinely carries no provider label).
	FactProvider FactSet = 1 << iota
	// FactInstance — Instance was resolved. Set together with FactProvider by
	// every gate that splits a label; kept separate so a future gate that knows
	// the provider but not the profile can say so.
	FactInstance
	// FactBrokerable — the provider's template was consulted for a
	// per-operation route.
	FactBrokerable
)

// Has reports whether every fact in x was established.
func (f FactSet) Has(x FactSet) bool { return f&x == x }

// matchDerived applies the fail-closed asymmetry to one server-derived string
// matcher, and reports whether the rule still matches.
//
// Three cases, and the middle one is the whole point:
//
//	pattern empty      → the rule does not constrain this fact; matches.
//	fact not computed  → unevaluable. A deny/ask rule MATCHES anyway (the
//	                     unchecked condition could only have narrowed it
//	                     further); an allow rule does NOT (granting on a
//	                     condition nobody evaluated is the failure above).
//	fact computed      → ordinary glob.
func matchDerived(pattern, value string, known bool, effect Effect) bool {
	if pattern == "" {
		return true
	}
	if !known {
		return effect != EffectAllow
	}
	return globMatch(pattern, value)
}
