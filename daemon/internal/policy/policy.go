// Package policy evaluates local, user-authored rules at the daemon's
// retrieval choke point. Every path that hands secret material to an agent —
// /retrieve, /assume, /resolve (the helper), /grant — asks the engine first.
//
// The policy lives in ~/.akasha/policy.yaml and is pure data: first-match
// rules over the request context (agent, action, provider, category, risk,
// tool) deciding allow, deny, or ask. "ask" pauses the operation for an
// interactive human decision and fails closed — no response means deny.
//
// No policy file means allow-everything, preserving pre-policy behaviour.
// A file that exists but cannot be parsed denies everything: a security
// control that silently stops applying is worse than one that fails loudly.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
	EffectAsk   Effect = "ask"
)

// Provenance records HOW the daemon came to believe an identity field, which
// determines whether a rule may grant access on the strength of it.
//
// The zero value is Asserted: a Request built without stating a provenance is
// treated as untrusted, so forgetting to set one can only ever restrict.
type Provenance uint8

const (
	// Asserted — the caller put the value in the request body. Forgeable by
	// anyone who can reach the socket. Only /wrap, /store, /retrieve and
	// /grant read identity this way.
	Asserted Provenance = iota

	// ServerAssigned — the daemon chose the value from the endpoint that ran
	// and ignored the body entirely (akasha-helper on /resolve, akasha-list on
	// /label/list, and so on). Not forgeable: a caller cannot pick which
	// literal a handler passes.
	ServerAssigned

	// Verified — backed by a valid X-Akasha-Key, checked against the vault.
	Verified
)

// Trusted reports whether a rule may satisfy an `allow` on the strength of
// this field.
func (p Provenance) Trusted() bool { return p != Asserted }

// String is the label written to the audit log, so a reader can tell an
// authenticated actor from one that merely claimed a name.
func (p Provenance) String() string {
	switch p {
	case Verified:
		return "verified"
	case ServerAssigned:
		return "server"
	default:
		return "asserted"
	}
}

// Request is the context available at the choke point for one operation.
//
// The fields divide into two classes and rules must be written knowing which
// is which:
//
//   - SERVER-DERIVED (Action, Provider, Instance, Category, Risk): the daemon
//     establishes these from the endpoint that ran and the vault entry itself.
//     A caller cannot choose them.
//   - IDENTITY (AgentID, Tool): trustworthy or not depending on the matching
//     AgentSource / ToolSource. See Provenance.
//
// This distinction is not decorative — a shipped policy permitted the broker
// with `tool: akasha_helper`, and since that is a body field, writing the
// string was enough to read raw secrets.
type Request struct {
	Action   string // retrieve | broker | assume | grant | inspect | list | bind | purge
	AgentID  string
	Tool     string // requesting tool (vault_retrieve caller, akasha_assume, akasha_helper, …)
	Provider string // assume path: template/provider name (aws, github, …)
	Instance string // assume path: profile/instance name
	Category string // vault entry classification (SSN, AWSAPIKey, Credential, …)
	Risk     string // vault entry risk: low | medium | high | critical
	Token    string
	Task     string // agent-supplied task description (display only — never matched)

	// How AgentID and Tool were established. Zero value (Asserted) is the
	// untrusted one, so an unset source can only ever restrict.
	AgentSource Provenance
	ToolSource  Provenance

	// Sandboxed reports whether the caller IS a supervised run — a
	// daemon-derived fact, established by the run key the request
	// authenticated with rather than by anything the caller sent. That makes it
	// the most trustworthy matcher available: unlike Tool, it cannot be written
	// into a request body.
	//
	// It is deliberately not "arrived on the run's private socket". A listener
	// is not an identity: the same run key reaches the daemon's own unix socket
	// and its loopback port, so a fact keyed on which listener accepted the
	// connection was false for every request that took another route.
	//
	// Its trustworthiness is bounded by the run key: an adversary holding that
	// key presents as sandboxed. Stronger than anything caller-asserted; not a
	// cryptographic guarantee.
	Sandboxed bool

	// Human is true when the caller authenticated as the local CLI acting as
	// the person. Like Sandboxed it is established from the verified key, so a
	// request body cannot assert it and a rule matching on it may grant.
	Human bool

	// Brokerable is true when this provider's TEMPLATE declares a
	// per-operation route — a helper delivery plus an ownership mechanism that
	// vends. The daemon reads it from the loaded template, so a caller cannot
	// assert it, and a rule may grant on it.
	//
	// It exists so that "an agent uses this per operation rather than holding a
	// session credential" is a rule an operator writes, keyed on something the
	// template declares — rather than a branch in the daemon. A provider with
	// no alternative route (ssh, gcp) simply does not match, so no rule has to
	// enumerate providers to avoid breaking them.
	Brokerable bool

	// Known records which of the server-derived facts above this gate actually
	// ESTABLISHED, as opposed to left at a zero value. See facts.go: for
	// Provider, Instance and Brokerable the zero value is also a real answer,
	// so without this the engine cannot tell "no provider" from "never asked"
	// — and answered the second one by falling through to the default.
	//
	// A gate that populates one of those fields must say so here. A gate that
	// populates none gets the safe direction for free.
	Known FactSet
}

// Rule is one first-match policy rule. Empty matcher fields match anything;
// glob patterns (* and ?) are supported in the string matchers. MinRisk
// matches any request at or above the named level.
type Rule struct {
	Action   string `yaml:"action,omitempty"`
	Agent    string `yaml:"agent,omitempty"`
	Tool     string `yaml:"tool,omitempty"`
	Provider string `yaml:"provider,omitempty"`
	Instance string `yaml:"instance,omitempty"`
	Category string `yaml:"category,omitempty"`
	MinRisk  string `yaml:"min_risk,omitempty"`
	// Sandbox gates on supervised launch. A POINTER so nil means "don't care":
	// a plain bool's zero value would make every existing rule suddenly match
	// only unsandboxed callers, silently changing every policy file in the
	// wild.
	Sandbox *bool `yaml:"sandbox,omitempty"`
	// Caller gates on WHO is asking: "human" (the local CLI) or "agent".
	//
	// A plain string, not a pointer like Sandbox: "" is already the natural
	// "don't care" for a string, whereas a bool's zero value is a MEANINGFUL
	// value, which is the whole reason Sandbox needed one.
	//
	// This is what expresses "agents broker production, humans may assume it"
	// in one rule — the distinction an operator actually thinks in, on an input
	// they cannot forge.
	Caller string `yaml:"caller,omitempty"`
	// Brokerable gates on whether the provider has a per-operation route.
	// A POINTER, for the same reason as Sandbox: a bool's zero value is a
	// meaningful value, so nil has to mean "don't care".
	Brokerable *bool  `yaml:"brokerable,omitempty"`
	Effect     Effect `yaml:"effect"`
	Reason     string `yaml:"reason,omitempty"`

	// unknown lists matcher keys this daemon does not recognize. See
	// ParseLenient: a rule written for a newer daemon is honoured as far as
	// this one can evaluate it, and refused an allow it cannot fully check.
	unknown []string
}

// UnknownMatchers reports the matcher keys this daemon did not recognize.
func (r Rule) UnknownMatchers() []string { return r.unknown }

// knownRuleKeys is the matcher vocabulary this daemon understands. It is
// enumerated rather than reflected because a typo in a struct tag would
// otherwise silently widen what counts as "known".
var knownRuleKeys = map[string]bool{
	"action": true, "agent": true, "tool": true, "provider": true,
	"instance": true, "category": true, "min_risk": true, "sandbox": true,
	"caller": true, "brokerable": true, "effect": true, "reason": true,
}

// knownDocKeys is the document vocabulary. Unlike a matcher, an unknown key
// HERE stays fatal: a document key defines what the file means, and guessing at
// a document whose meaning is unknown is not something a policy engine may do.
// This is the same line the template loader draws.
var knownDocKeys = map[string]bool{
	"version": true, "default": true, "ask_timeout_seconds": true,
	"ask_requires": true, "rules": true,
}

// Policy is the parsed ~/.akasha/policy.yaml.
type Policy struct {
	Version           int    `yaml:"version"`
	Default           Effect `yaml:"default,omitempty"` // allow (default) or deny
	AskTimeoutSeconds int    `yaml:"ask_timeout_seconds,omitempty"`
	// AskRequires is how strong an `ask` has to be: "click" (a dialog button,
	// the default) or "passphrase". Document-level rather than per-rule, which
	// is the same shape as AskTimeoutSeconds and for the same reason: Decision
	// carries no payload, so a rule cannot hand a value to a call site. See
	// presence.go.
	AskRequires string `yaml:"ask_requires,omitempty"`
	Rules       []Rule `yaml:"rules,omitempty"`
}

// Decision is the outcome of evaluating a request against the policy.
type Decision struct {
	Effect Effect
	Reason string // rule reason, or a generated description
}

var riskOrder = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// RiskRank returns a risk level's ordinal and whether it was recognised.
//
// The second return is the point: an unrecognised risk is NOT "the lowest
// level", it is "we do not know". Treating unknown as 0 is what let a caller
// classify an entry out of policy's reach — see the MinRisk handling in
// matches, and ValidRisk for the ingest-side guard that stops such an entry
// being stored in the first place.
func RiskRank(risk string) (int, bool) {
	n, ok := riskOrder[strings.ToLower(strings.TrimSpace(risk))]
	return n, ok
}

// ValidRisk reports whether risk is one of the four levels the engine can rank.
// Callers that persist a risk label must reject anything else, or the entry
// becomes permanently invisible to every min_risk rule.
func ValidRisk(risk string) bool {
	_, ok := RiskRank(risk)
	return ok
}

// RiskLevels lists the accepted values, for error messages and validation.
func RiskLevels() []string { return []string{"low", "medium", "high", "critical"} }

// ValidCategory reports whether a category is one a rule can name.
//
// Unlike risk this is NOT a closed ladder — the classifier config lets a user
// define their own categories (EmployeeID, TicketRef, …) and refusing those
// would turn a documented feature into a policy blind spot. What it enforces is
// that the label is a usable identifier at all: a blank, padded, or
// punctuation-laden category is one no `category:` rule can be written against,
// which is the same "invisible to policy" hole ValidRisk closes on the other
// axis. Callers that persist a category must reject anything else.
func ValidCategory(category string) bool {
	if category == "" || category != strings.TrimSpace(category) || len(category) > 64 {
		return false
	}
	for _, r := range category {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// CategoryLevels lists the categories Akasha itself assigns, for error messages
// and documentation. It is a hint, not an allowlist: ValidCategory accepts any
// well-formed name so user-defined classifier patterns keep working.
func CategoryLevels() []string {
	return []string{"SSN", "CreditCard", "Email", "Phone", "APIKey", "Password",
		"BankAccount", "IPAddress", "RiskyTool", "Credential", "CredentialMap",
		"UserSecret", "Unknown"}
}

// DefaultPath returns ~/.akasha/policy.yaml.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "policy.yaml")
}

// Parse decodes and validates a policy document strictly: any unknown field is
// an error. This is the AUTHORING path — `akasha policy validate` — where a
// typo must be caught loudly, because a misspelled matcher is a rule that does
// not do what its author believes.
func Parse(data []byte) (*Policy, error) { return parse(data, true) }

// ParseLenient is Parse for the DAEMON, and it tolerates exactly one thing: a
// matcher key this daemon does not recognize.
//
// Every new matcher was a one-way door. The parser was strict with no lenient
// path, there is no min_daemon gate, and a parse error makes Authorize deny
// EVERY operation — so a user who adopted a new key and then ran an older
// daemon lost all access. Not degraded security: a total outage. That cost
// compounds with every matcher the vocabulary ever gains, and `sandbox` had
// already been added once.
//
// The tolerance is fail-closed, borrowing the asymmetry this package already
// uses for a risk it cannot rank: an unrecognized condition MATCHES a deny or
// ask rule, and prevents an allow rule from matching. A downgrade therefore
// degrades to "some allow rules stop firing" — strictly more restrictive —
// instead of locking the machine.
//
// A malformed document, and an unknown key at the DOCUMENT level, both stay
// fatal. Only a rule's matcher is forgiven.
func ParseLenient(data []byte) (*Policy, error) { return parse(data, false) }

func parse(data []byte, strict bool) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	err := dec.Decode(&p)
	if err != nil && !strict {
		var lerr error
		p, lerr = parseTolerant(data)
		if lerr != nil {
			return nil, lerr
		}
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Default == "" {
		p.Default = EffectAllow
	}
	if p.Default != EffectAllow && p.Default != EffectDeny {
		return nil, fmt.Errorf("policy default must be allow or deny, got %q", p.Default)
	}
	if err := validAskRequires(p.AskRequires); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.AskRequires == "" {
		p.AskRequires = AskClick
	}
	if p.AskTimeoutSeconds <= 0 {
		p.AskTimeoutSeconds = 60
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		switch r.Effect {
		case EffectAllow, EffectDeny, EffectAsk:
		default:
			return nil, fmt.Errorf("rule %d: effect must be allow, deny or ask, got %q", i+1, r.Effect)
		}
		if r.MinRisk != "" {
			if _, ok := riskOrder[r.MinRisk]; !ok {
				return nil, fmt.Errorf("rule %d: min_risk must be low, medium, high or critical, got %q", i+1, r.MinRisk)
			}
		}
		switch r.Caller {
		case "", "human", "agent":
		default:
			return nil, fmt.Errorf("rule %d: caller must be human or agent, got %q", i+1, r.Caller)
		}
		switch r.Action {
		// "describe" derives non-secret facts about a credential (which account,
		// which principal) and can never return the credential itself. It is
		// listed separately from "retrieve"/"assume" so an operator can allow
		// "which account is this?" broadly while keeping the secret-yielding
		// actions tight. Named to match the deliver mode it gates, and to keep
		// every action in this list a verb.
		case "", "retrieve", "broker", "assume", "grant", "inspect", "describe", "list", "bind", "purge":
		default:
			return nil, fmt.Errorf("rule %d: action must be retrieve, broker, assume, grant, inspect, describe, list, bind or purge, got %q", i+1, r.Action)
		}
	}
	return &p, nil
}

// parseTolerant re-decodes a document the strict pass rejected, keeping only the
// unknown MATCHER case and re-failing everything else.
//
// It re-reads the raw document rather than trusting the strict error text: the
// error names one field, and a file can carry several. Comparing the keys that
// are actually present against the vocabulary is the only way to know which
// rules are affected, and it is what lets matches() treat them individually.
func parseTolerant(data []byte) (Policy, error) {
	var p Policy

	// A document-level unknown key is still fatal.
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(data, &top); err != nil {
		return p, fmt.Errorf("parse policy: %w", err)
	}
	for k := range top {
		if !knownDocKeys[k] {
			return p, fmt.Errorf("parse policy: unknown top-level key %q "+
				"(a document key defines what the file means, so it is not guessed at)", k)
		}
	}

	// Now decode without the strict flag. Anything still failing is malformed
	// rather than merely newer, and stays fatal.
	if err := yaml.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse policy: %w", err)
	}

	// Record which rules carried keys this daemon does not know.
	var raw struct {
		Rules []map[string]yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return p, fmt.Errorf("parse policy: %w", err)
	}
	for i := range p.Rules {
		if i >= len(raw.Rules) {
			break
		}
		for k := range raw.Rules[i] {
			if !knownRuleKeys[k] {
				p.Rules[i].unknown = append(p.Rules[i].unknown, k)
			}
		}
		sort.Strings(p.Rules[i].unknown)
	}
	return p, nil
}

// callerKind renders Request.Human as the vocabulary a rule is written in.
func callerKind(human bool) string {
	if human {
		return "human"
	}
	return "agent"
}

// Evaluate returns the first matching rule's decision, or the default.
func (p *Policy) Evaluate(req Request) Decision {
	for i, r := range p.Rules {
		if !r.matches(req) {
			continue
		}
		reason := r.Reason
		if reason == "" {
			reason = fmt.Sprintf("policy rule %d", i+1)
		}
		return Decision{Effect: r.Effect, Reason: reason}
	}
	return Decision{Effect: p.Default, Reason: "policy default"}
}

func (r Rule) matches(req Request) bool {
	// An asserted identity may NARROW a deny; it may never SATISFY an allow.
	//
	// `agent:` and `tool:` are body fields on /wrap, /store, /retrieve and
	// /grant, so a rule that grants access on their strength is self-service —
	// the caller picks the value. Restrictive effects are unaffected: matching
	// a deny or ask against an asserted value is safe, because a caller only
	// ever hurts itself by lying about who it is.
	//
	// This is deliberately keyed on ASSERTION, not on the absence of a key.
	// Most endpoints ignore the body and pass a literal the daemon chose
	// (akasha-helper, akasha-list, …); those are ServerAssigned and not
	// forgeable, so rules written against them keep granting.
	// A matcher this daemon cannot evaluate is a condition it cannot claim to
	// have applied. It may still NARROW — a deny or ask rule fires on what can
	// be checked, and the unevaluated condition could only have restricted it
	// further — but it may never GRANT.
	if len(r.unknown) > 0 && r.Effect == EffectAllow {
		return false
	}
	if r.Effect == EffectAllow {
		if r.Agent != "" && !req.AgentSource.Trusted() {
			return false
		}
		if r.Tool != "" && !req.ToolSource.Trusted() {
			return false
		}
	}
	if !globMatch(r.Action, req.Action) ||
		!globMatch(r.Agent, req.AgentID) ||
		!globMatch(r.Tool, req.Tool) {
		return false
	}
	// Provider and Instance are server-derived and NOT self-describing: "" is
	// both "this entry has no provider" and "this gate never resolved one". A
	// gate that did not look must not be able to satisfy a deny rule's
	// absence — see facts.go for the reproduction that made this necessary.
	if !matchDerived(r.Provider, req.Provider, req.Known.Has(FactProvider), r.Effect) ||
		!matchDerived(r.Instance, req.Instance, req.Known.Has(FactInstance), r.Effect) {
		return false
	}
	if r.Category != "" {
		switch {
		case !ValidCategory(req.Category):
			// A category the engine cannot read — blank, or a label no rule can
			// name. Fail CLOSED in both directions, exactly as MinRisk does
			// below: a deny/ask rule MATCHES it, because "deny anything
			// classified SSN" must not be escaped by storing the loot with no
			// usable classification at all; an allow rule does NOT, because
			// granting on a classification we could not read is the same
			// mistake with the sign flipped.
			if r.Effect == EffectAllow {
				return false
			}
		case !globMatch(r.Category, req.Category):
			return false
		}
	}
	if r.Sandbox != nil && *r.Sandbox != req.Sandboxed {
		return false
	}
	// Daemon-derived like Sandbox, so no provenance gate: an allow rule may
	// safely turn on it.
	if r.Caller != "" && r.Caller != callerKind(req.Human) {
		return false
	}
	if r.Brokerable != nil {
		switch {
		case !req.Known.Has(FactBrokerable):
			// Nobody consulted the template. Restrictive rules still bind;
			// a rule that GRANTS on "this has a per-operation route" may not,
			// because the route was never established to exist.
			if r.Effect == EffectAllow {
				return false
			}
		case *r.Brokerable != req.Brokerable:
			return false
		}
	}
	if r.MinRisk != "" {
		got, known := RiskRank(req.Risk)
		switch {
		case !known:
			// Unknown or unclassified risk. Fail CLOSED in both directions,
			// which means opposite things for the two kinds of rule:
			//
			//   deny/ask — the rule MATCHES. "Deny anything high or above"
			//     must cover a request whose risk we cannot rank, or an
			//     unrankable entry slips past every restrictive rule and lands
			//     on the default. That was the bug: riskOrder[""] == 0 sorted
			//     below every threshold, so `{min_risk: low, effect: deny}`
			//     silently failed to apply, and a caller who stored an entry
			//     with risk "criticall" made it invisible to policy entirely.
			//
			//   allow — the rule does NOT match. Granting on the strength of a
			//     risk level we could not read would be the same mistake with
			//     the sign flipped.
			if r.Effect == EffectAllow {
				return false
			}
		case got < riskOrder[r.MinRisk]:
			return false
		}
	}
	return true
}

// globMatch reports whether value matches pattern. An empty pattern matches
// anything. Patterns support * (any run of any characters, including "/") and
// ? (any single character); every other character is literal. Matching is
// case-insensitive.
//
// This deliberately does NOT use filepath.Match. That function matches PATHS,
// so its "*" stops at a separator — and the values matched here are not paths
// but identifiers, some of which contain slashes. The escrow label POLICY.md
// documented at the time is the case that broke:
//
//	label:    escrow:/Users/me/.aws/credentials
//	instance: /Users/me/.aws/credentials
//	rule:     {provider: escrow, instance: "*", effect: ask}   ← never matched
//
// "*" could not cross the four separators, so a rule that reads as "approve
// every escrow read" silently matched nothing and fell through to the default.
// A security rule that quietly fails to apply is worse than one that errors.
//
// Dropping filepath.Match also removes ErrBadPattern from the picture. It had
// no good handling: an unparseable pattern either matched nothing (a deny rule
// that silently stops applying) or everything (an allow rule that opens up).
// Here every pattern is valid — "[" and "\" are ordinary characters — so that
// failure mode no longer exists, and the supported syntax is exactly the "*"
// and "?" the docs advertise.
func globMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	return wildcardMatch([]rune(strings.ToLower(pattern)), []rune(strings.ToLower(value)))
}

// wildcardMatch is the standard linear-with-backtracking wildcard matcher:
// walk both inputs, and on a mismatch fall back to the most recent "*" and let
// it absorb one more character. Runes rather than bytes so "?" matches one
// character, not one byte of a multi-byte one.
func wildcardMatch(pattern, value []rune) bool {
	var p, v int
	starP, starV := -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]):
			p++
			v++
		case p < len(pattern) && pattern[p] == '*':
			starP, starV = p, v
			p++
		case starP >= 0:
			starV++
			p, v = starP+1, starV
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// ─── Engine ─────────────────────────────────────────────────────────────────

// Approver resolves an "ask" decision interactively. Implementations must
// fail closed: any error, timeout, or ambiguity is a deny.
type Approver interface {
	Approve(req Request, timeout time.Duration) bool
}

// Engine loads the policy file lazily with mtime caching, so edits to
// policy.yaml take effect on the next operation without a daemon restart.
// StateStore remembers, across daemon restarts, that a policy was installed.
//
// Without it the engine cannot tell "you have never configured a policy" from
// "your policy was deleted a second ago" — both are just a missing file — so
// `rm ~/.akasha/policy.yaml` silently turned the control off. The vault
// implements this; it is an interface so the policy package does not depend on
// the vault.
type StateStore interface {
	PolicyState() (digest string, err error)
	SetPolicyState(digest string) error
}

// Notifier receives policy lifecycle events. Kept as a callback rather than an
// audit dependency so this package stays leaf-ish; the server hands it one that
// writes to the audit log.
type Notifier func(action, detail string)

// Lifecycle actions passed to a Notifier.
const (
	EventLoaded  = "POLICY_LOADED"
	EventChanged = "POLICY_CHANGED"
	EventMissing = "POLICY_MISSING"
)

type Engine struct {
	path string

	mu      sync.Mutex
	cached  *Policy
	loadErr error
	digest  string

	state  StateStore
	notify Notifier

	approver Approver
	verifier PassphraseVerifier
	// askMu serialises interactive approvals; see Engine.ask.
	askMu sync.Mutex
}

// SetStateStore enables deleted-policy detection. Without a store the engine
// keeps the original opt-in behaviour: a missing file allows everything.
func (e *Engine) SetStateStore(s StateStore) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = s
}

// SetNotifier registers a callback for load/change/missing events.
func (e *Engine) SetNotifier(fn Notifier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notify = fn
}

// NewEngine returns an engine reading path, with the platform's interactive
// approver for "ask" rules.
func NewEngine(path string) *Engine {
	return &Engine{path: path, approver: platformApprover()}
}

// SetApprover replaces the interactive approver (tests, future GUI/menubar).
func (e *Engine) SetApprover(a Approver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.approver = a
}

// ask resolves an EffectAsk decision, serialising approvals across the whole
// engine.
//
// Approvals were previously unserialised: the HTTP server runs a goroutine per
// request, so N concurrent gated operations opened N modal dialogs at once,
// with no cap, no dedupe, and no cooldown after a deny. Flooding a user until
// they click Allow on one is a practical attack, and it is worse when several
// identical-looking dialogs are stacked and only one is the dangerous request.
//
// The lock lives here rather than in dialogApprover so it applies to every
// Approver implementation, including the menubar/GUI one SetApprover exists
// for. It is a separate mutex from e.mu on purpose — holding the policy lock
// for the length of a human decision would stall every other evaluation.
func (e *Engine) ask(req Request, timeout time.Duration) bool {
	e.mu.Lock()
	approver := e.approver
	e.mu.Unlock()
	if approver == nil {
		return false
	}

	e.askMu.Lock()
	defer e.askMu.Unlock()
	return approver.Approve(req, timeout)
}

// current returns the parsed policy, reloading if the file changed. A missing
// file yields the permissive default policy; an unreadable or invalid file
// yields (nil, error) — which Authorize treats as deny-everything.
func (e *Engine) current() (*Policy, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := os.ReadFile(e.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		// A missing file means one of two very different things, and the
		// filesystem cannot tell them apart. Ask the state store.
		if installed, _ := e.installedDigest(); installed != "" {
			e.cached, e.loadErr, e.digest = nil, nil, ""
			e.emit(EventMissing, "policy file "+e.path+" is gone but a policy was installed")
			return nil, fmt.Errorf(
				"policy file %s is missing but a policy was previously installed — "+
					"restore it, or run `akasha policy disable` if you meant to turn policy off",
				e.path)
		}
		// Never configured: opt-in, allow everything. This is the documented
		// first-run behaviour and must survive.
		return &Policy{Default: EffectAllow, AskTimeoutSeconds: 60}, nil
	}

	// Cache on the CONTENT digest, not (mtime, size). The old cache captured
	// the stat BEFORE reading, so the cached bytes and the cached stat could
	// describe different file states: write a permissive policy, let it load,
	// then restore the original padded to the same length with `touch -r`, and
	// the daemon went on enforcing the attacker's copy while `cat` and `akasha
	// policy validate` both showed the real one. Reading every time costs one
	// small page-cached read per gated operation, which is the right trade for
	// a control that must not be pinnable.
	d := digestOf(data)
	if d == e.digest && (e.cached != nil || e.loadErr != nil) {
		return e.cached, e.loadErr
	}

	first := e.digest == ""
	e.cached, e.loadErr = ParseLenient(data)
	e.digest = d

	if e.loadErr == nil {
		// Record only a policy that actually parsed: a file we could not read
		// must not arm the "was installed" tripwire, or a syntax error would
		// wedge the daemon into deny-all with no obvious way out.
		if e.state != nil {
			_ = e.state.SetPolicyState(d)
		}
		if first {
			e.emit(EventLoaded, "loaded "+e.path)
		} else {
			e.emit(EventChanged, "reloaded "+e.path+" after an edit")
		}
	} else {
		e.emit(EventChanged, "policy file "+e.path+" is invalid: "+e.loadErr.Error())
	}
	return e.cached, e.loadErr
}

// installedDigest reports the digest recorded by a previous successful load.
func (e *Engine) installedDigest() (string, error) {
	if e.state == nil {
		return "", nil
	}
	return e.state.PolicyState()
}

// emit fires a lifecycle notification if one is registered. Called with e.mu
// held, so the callback must not re-enter the engine.
func (e *Engine) emit(action, detail string) {
	if e.notify != nil {
		e.notify(action, detail)
	}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Authorize evaluates the request and resolves "ask" interactively.
// A nil return means the operation may proceed; otherwise the error explains
// the denial (safe to surface to the agent).
func (e *Engine) Authorize(req Request) error {
	p, err := e.current()
	if err != nil {
		// Fail closed, loudly: a broken policy file must not silently
		// disable the control it exists to provide.
		return fmt.Errorf("policy file %s is invalid (denying all operations until fixed): %v", e.path, err)
	}
	d := p.Evaluate(req)
	switch d.Effect {
	case EffectAllow:
		return nil
	case EffectDeny:
		return fmt.Errorf("denied by policy: %s", d.Reason)
	case EffectAsk:
		e.mu.Lock()
		approver := e.approver
		e.mu.Unlock()
		if approver == nil {
			return fmt.Errorf("denied by policy: %s (approval required but no approver available)", d.Reason)
		}
		// An approver can exist and still have no way to reach a human — no
		// graphical session, no dialog program. Report which, so the operator
		// fixes the channel instead of hunting for a decision nobody made.
		if u, ok := approver.(unavailableApprover); ok {
			if why := u.Unavailable(); why != "" {
				return fmt.Errorf("denied by policy: %s (approval required but unavailable: %s)", d.Reason, why)
			}
		}
		granted, why := e.presenceApprove(req, p.AskRequires, time.Duration(p.AskTimeoutSeconds)*time.Second)
		if why != "" {
			// The approval could not be OBTAINED, which is not the same as a
			// human declining. Naming it keeps a denial from reading as a
			// decision nobody made — the same distinction unavailableApprover
			// already draws for a missing dialog.
			return fmt.Errorf("denied: %s (rule: %s)", why, d.Reason)
		}
		if granted {
			return nil
		}
		return fmt.Errorf("denied by policy: %s (approval not granted)", d.Reason)
	}
	return fmt.Errorf("denied by policy: unknown effect %q", d.Effect)
}
