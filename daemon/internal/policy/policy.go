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
	Effect   Effect `yaml:"effect"`
	Reason   string `yaml:"reason,omitempty"`
}

// Policy is the parsed ~/.akasha/policy.yaml.
type Policy struct {
	Version           int    `yaml:"version"`
	Default           Effect `yaml:"default,omitempty"` // allow (default) or deny
	AskTimeoutSeconds int    `yaml:"ask_timeout_seconds,omitempty"`
	Rules             []Rule `yaml:"rules,omitempty"`
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

// DefaultPath returns ~/.akasha/policy.yaml.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "policy.yaml")
}

// Parse decodes and validates a policy document (strict: unknown fields are
// errors, like the template loader).
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Default == "" {
		p.Default = EffectAllow
	}
	if p.Default != EffectAllow && p.Default != EffectDeny {
		return nil, fmt.Errorf("policy default must be allow or deny, got %q", p.Default)
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
		switch r.Action {
		case "", "retrieve", "broker", "assume", "grant", "inspect", "list", "bind", "purge":
		default:
			return nil, fmt.Errorf("rule %d: action must be retrieve, broker, assume, grant, inspect, list, bind or purge, got %q", i+1, r.Action)
		}
	}
	return &p, nil
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
		!globMatch(r.Tool, req.Tool) ||
		!globMatch(r.Provider, req.Provider) ||
		!globMatch(r.Instance, req.Instance) ||
		!globMatch(r.Category, req.Category) {
		return false
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
// but identifiers, some of which contain slashes. The escrow label documented
// in POLICY.md is the case that broke:
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
	e.cached, e.loadErr = Parse(data)
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
		haveApprover := e.approver != nil
		e.mu.Unlock()
		if !haveApprover {
			return fmt.Errorf("denied by policy: %s (approval required but no approver available)", d.Reason)
		}
		if e.ask(req, time.Duration(p.AskTimeoutSeconds)*time.Second) {
			return nil
		}
		return fmt.Errorf("denied by policy: %s (approval not granted)", d.Reason)
	}
	return fmt.Errorf("denied by policy: unknown effect %q", d.Effect)
}
