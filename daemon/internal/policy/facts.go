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
	// FactInstance — Instance was resolved.
	//
	// Always set TOGETHER with FactProvider today, because WithLabel and NoLabel
	// are the only ways to resolve either and both set the pair. The bits stay
	// separate because the MATCHER reads them separately, not because a caller
	// can currently split them.
	//
	// Do not read this as "a gate that knows the provider but not the profile
	// can say so" — it cannot, and the spelling an author would reach for,
	// WithLabel(provider, provider, ""), asserts the PERMISSIVE answer: instance
	// resolved-and-empty, which `{instance: "*", effect: allow}` then matches.
	// Splitting them means adding a WithProvider that sets FactProvider alone.
	FactInstance
	// FactBrokerable — the provider's template was consulted for a
	// per-operation route.
	FactBrokerable
)

// Has reports whether every fact in x was established.
func (f FactSet) Has(x FactSet) bool { return f&x == x }

// ─── What a gate acts on ────────────────────────────────────────────────────

// SubjectKind names WHAT one operation acts on. It is the whole of a gate's
// contribution to the server-derived half of a request: the gate says what it is
// touching, and a FactResolver works out what that implies.
//
// The split exists because there was no split. Every gate hand-populated the
// derived fields of a Request, and no two gates populated the same subset — so
// `{provider: aws, effect: deny}` bound on /assume, which set Provider, and not
// on /retrieve, which did not. Six copies of a derivation is six chances to get
// it wrong, and the sixth was written by someone who had read the other five.
type SubjectKind uint8

const (
	// SubjectUnset is the zero value, and it is deliberately NOT the
	// vault-wide kind.
	//
	// "This operation names no provider" is the one answer that widens: it is
	// resolved-and-empty, so a provider-scoped deny rule stops applying to it.
	// Making that the zero value would mean a gate that forgot to say what it
	// acts on silently got the permissive reading — the original bug, moved
	// rather than removed. A resolver must refuse this kind.
	SubjectUnset SubjectKind = iota

	// SubjectVault — the operation is vault-wide and names no credential:
	// /label/list, /vault/purge. The daemon HAS established that no provider is
	// involved, which is a different statement from never having looked.
	SubjectVault

	// SubjectToken — the subject is a vault token: /retrieve, /grant, /inspect.
	// Every label the token answers to is evaluated, and the entry's own
	// classification comes from the vault.
	SubjectToken

	// SubjectBinding — the subject is a label being pointed at a secret, or
	// taken away from one: /label/set, /put, /profile/save, /label/delete.
	SubjectBinding

	// SubjectCredential — the subject is a named credential whose value this
	// operation can hand back: /assume, /resolve, /identity,
	// /credential/retrieve. The only kind that consults the provider's template
	// for a per-operation route, because it is the only kind for which
	// "brokered instead" is a real alternative.
	SubjectCredential
)

// Subject is what one operation acts on — the QUESTION a gate asks. The answer
// (Facts) is derived from it, and cannot be written by hand.
//
// Its fields are unexported and the four constructors below are the only way to
// build one, so a gate states the kind of thing it is touching rather than
// stating what the rules should see.
type Subject struct {
	kind     SubjectKind
	name     string
	token    string
	category string
	risk     string
}

// VaultWide is the subject for an operation that names no credential at all.
//
// Only two doors are entitled to this answer, /label/list and /vault/purge, and
// choosing it wrongly is the one mistake this design cannot catch: a gate that
// DOES name a secret but declares itself vault-wide evaluates as
// resolved-and-empty and slips past every provider rule. Both uses carry that
// warning at the call site.
func VaultWide(category, risk string) Subject {
	return Subject{kind: SubjectVault, category: category, risk: risk}
}

// OfToken is the subject for a gate addressed by vault token rather than by
// name. The classification is read from the entry, so the gate supplies none.
func OfToken(token string) Subject {
	return Subject{kind: SubjectToken, token: token}
}

// OfBinding is the subject for pointing a label at a secret, or removing one.
// The caller supplies the classification because the risk of a bind depends on
// what it does to an existing name, which only the gate knows.
func OfBinding(name, token, category, risk string) Subject {
	return Subject{kind: SubjectBinding, name: name, token: token, category: category, risk: risk}
}

// OfCredential is the subject for a gate that can hand back a credential's
// value. The classification is passed in rather than decided here: what a
// credential action is worth is the daemon's judgement, and it stays where its
// rationale is written.
func OfCredential(name, token, category, risk string) Subject {
	return Subject{kind: SubjectCredential, name: name, token: token, category: category, risk: risk}
}

// Kind, Name, Token, Category and Risk are read by the FactResolver. The engine
// itself never looks inside a Subject — it only hands it over and evaluates what
// comes back.
func (s Subject) Kind() SubjectKind { return s.kind }
func (s Subject) Name() string      { return s.name }
func (s Subject) Token() string     { return s.token }
func (s Subject) Category() string  { return s.category }
func (s Subject) Risk() string      { return s.risk }

// ─── What that turns out to mean ────────────────────────────────────────────

// Facts is one fully-derived, server-side view of a Subject: the values every
// server-derived matcher reads, plus the record of which of them were actually
// established.
//
// Its fields are unexported, and every setter records the FactSet bit in the
// SAME statement that supplies the value. That is the point of the type:
// "supplied a value" and "declared it resolved" were two separate things a gate
// had to remember, they drifted apart, and a policy failed open. Here they
// cannot drift, because there is no way to write one without the other.
//
// The zero value establishes NOTHING, which is the safe direction — a view that
// says nothing is unevaluable, so deny and ask rules still bind and allow rules
// cannot. Anything that made a missing field default to resolved-and-empty would
// make forgetting cost the unsafe direction instead.
type Facts struct {
	label      string
	alias      bool
	provider   string
	instance   string
	category   string
	risk       string
	token      string
	brokerable bool
	known      FactSet
}

// WithLabel records the provider and instance one label splits into, and marks
// BOTH resolved in the same statement.
//
// label itself is carried for attribution only — it is never matched. A denial
// has to be able to say WHICH of a secret's names refused, or "denied by policy"
// on a request the caller made under a different name is unexplainable.
func (f Facts) WithLabel(label, provider, instance string) Facts {
	f.label, f.provider, f.instance = label, provider, instance
	f.known |= FactProvider | FactInstance
	return f
}

// NoLabel records that the daemon LOOKED and this operation names no provider:
// a vault-wide gate, or a secret that answers to no label.
//
// This is resolved-and-empty, and it is not the same as saying nothing. A
// provider-scoped rule naming a LITERAL does not match it — otherwise one
// `{provider: escrow, effect: deny}` would deny /vault/purge, /label/list and
// every unlabelled secret in the vault.
//
// A WILDCARD still matches, and that is not a bug to fix here: globMatch("*", "")
// is true, so `{provider: "*"}` covers vault-wide operations as well. An operator
// writing `*` means "anything", and a vault-wide sweep is one of the things they
// meant. The distinction matters when writing a rule that must reach only
// provider-bearing operations — `?*` requires at least one character and is the
// spelling for that; see TestGatesDeriveFromWhatTheyActuallyTouch, which relies
// on exactly this difference to tell a real subject from a vault-wide one.
func (f Facts) NoLabel() Facts {
	f.provider, f.instance = "", ""
	f.known |= FactProvider | FactInstance
	return f
}

// WithBrokerable records the answer the provider's TEMPLATE gave about a
// per-operation route. Only a gate that actually consulted a template may call
// it: `brokerable: false` is also what "nobody asked" looks like, and an allow
// rule must not fire on the second one.
func (f Facts) WithBrokerable(b bool) Facts {
	f.brokerable = b
	f.known |= FactBrokerable
	return f
}

// WithClassification records the entry's category and risk.
//
// No FactSet bit, and that is not an oversight: these two are SELF-DESCRIBING.
// An unrankable risk is visibly unrankable and a category no rule can name is
// visibly unnameable, so Rule.matches has always been able to fail closed on
// them without being told whether anyone looked. Provider, Instance and
// Brokerable are the three whose zero value is indistinguishable from a real
// answer, which is why they are the three with bits.
func (f Facts) WithClassification(category, risk string) Facts {
	f.category, f.risk = category, risk
	return f
}

// WithToken names the secret this view is about. Display and audit only — no
// rule matches on a token — but the DENIED event is unreadable without it.
func (f Facts) WithToken(token string) Facts {
	f.token = token
	return f
}

// AsAlias marks this view as one of the OTHER names the subject answers to,
// rather than the name the caller asked with. It is what lets a denial explain
// itself: the caller asked for zz:1 and the rule that refused is about aws:prod.
func (f Facts) AsAlias() Facts {
	f.alias = true
	return f
}

// Read-only accessors. A method is an engine-derived fact; a field is
// caller-supplied. The distinction is worth a few lines of boilerplate on a
// type where mixing the two is the failure mode.
func (f Facts) Label() string    { return f.label }
func (f Facts) IsAlias() bool    { return f.alias }
func (f Facts) Provider() string { return f.provider }
func (f Facts) Instance() string { return f.instance }
func (f Facts) Category() string { return f.category }
func (f Facts) Risk() string     { return f.risk }
func (f Facts) Token() string    { return f.token }
func (f Facts) Brokerable() bool { return f.brokerable }
func (f Facts) Known() FactSet   { return f.known }

// FactResolver derives the server-side facts about a Subject. There is exactly
// one implementation, in internal/server, and it is INJECTED rather than
// imported.
//
// Splitting a label into provider and instance, enumerating the other names a
// token answers to, reading a provider's template for a per-operation route and
// classifying what an action can hand back are all facts about the vault and the
// installed templates. This package must not learn any of them — the two-method
// StateStore next door exists for the same reason, and its comment says so.
type FactResolver interface {
	// FactsFor expands one subject into the set of views that must ALL pass.
	//
	// It must return at least one view: a secret reachable under two names is
	// governed by both names' rules, and a subject that resolves to no name at
	// all still has to be evaluated once, or the gate is skipped entirely for
	// every unlabelled secret.
	//
	// An error means the daemon could not establish what the subject IS —
	// distinct from a policy denial, because the rules were never applied.
	FactsFor(Subject) ([]Facts, error)
}

// unresolvedFacts is the FactResolver an Engine uses when nobody wired one.
//
// It establishes nothing: one view, Known == 0. Every provider, instance and
// brokerable rule therefore reads the request as unevaluable — restrictive rules
// still bind, permissive ones cannot — which is the same asymmetry matchDerived
// applies to a single unpopulated fact.
//
// Refusing outright was the other option and is worse: an Engine is usable on
// its own (`akasha policy validate`, this package's own tests), and one that
// denied everything until a vault was attached would make the leaf package
// depend on the daemon in practice if not in imports. What matters is that a
// missing resolver degrades toward refusal, and this does.
type unresolvedFacts struct{}

func (unresolvedFacts) FactsFor(Subject) ([]Facts, error) { return []Facts{{}}, nil }

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
