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

// Request is the context available at the choke point for one operation.
type Request struct {
	Action   string // retrieve | assume | grant | inspect | list
	AgentID  string
	Tool     string // requesting tool (vault_retrieve caller, akasha_assume, akasha_helper, …)
	Provider string // assume path: template/provider name (aws, github, …)
	Instance string // assume path: profile/instance name
	Category string // vault entry classification (SSN, AWSAPIKey, Credential, …)
	Risk     string // vault entry risk: low | medium | high | critical
	Token    string
	Task     string // agent-supplied task description (display only — never matched)
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
		case "", "retrieve", "assume", "grant", "inspect", "list":
		default:
			return nil, fmt.Errorf("rule %d: action must be retrieve, assume, grant, inspect or list, got %q", i+1, r.Action)
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
	if !globMatch(r.Action, req.Action) ||
		!globMatch(r.Agent, req.AgentID) ||
		!globMatch(r.Tool, req.Tool) ||
		!globMatch(r.Provider, req.Provider) ||
		!globMatch(r.Instance, req.Instance) ||
		!globMatch(r.Category, req.Category) {
		return false
	}
	if r.MinRisk != "" {
		if riskOrder[strings.ToLower(req.Risk)] < riskOrder[r.MinRisk] {
			return false
		}
	}
	return true
}

// globMatch reports whether value matches pattern. An empty pattern matches
// anything. Patterns support * (any run) and ? (any single char); matching is
// case-insensitive. A malformed pattern matches nothing (fail closed would
// invert to "matches everything" for deny rules — but a rule that can't be
// parsed shouldn't silently apply either way, so validation should catch it;
// here we simply don't match).
func globMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	ok, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(value))
	return err == nil && ok
}

// ─── Engine ─────────────────────────────────────────────────────────────────

// Approver resolves an "ask" decision interactively. Implementations must
// fail closed: any error, timeout, or ambiguity is a deny.
type Approver interface {
	Approve(req Request, timeout time.Duration) bool
}

// Engine loads the policy file lazily with mtime caching, so edits to
// policy.yaml take effect on the next operation without a daemon restart.
type Engine struct {
	path string

	mu      sync.Mutex
	cached  *Policy
	loadErr error
	mtime   time.Time
	size    int64

	approver Approver
}

// NewEngine returns an engine reading path, with the platform's interactive
// approver for "ask" rules.
func NewEngine(path string) *Engine {
	return &Engine{path: path, approver: platformApprover()}
}

// SetApprover replaces the interactive approver (tests, future GUI/menubar).
func (e *Engine) SetApprover(a Approver) { e.approver = a }

// current returns the parsed policy, reloading if the file changed. A missing
// file yields the permissive default policy; an unreadable or invalid file
// yields (nil, error) — which Authorize treats as deny-everything.
func (e *Engine) current() (*Policy, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	st, err := os.Stat(e.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Policy{Default: EffectAllow, AskTimeoutSeconds: 60}, nil
		}
		return nil, err
	}
	if e.cached != nil || e.loadErr != nil {
		if st.ModTime().Equal(e.mtime) && st.Size() == e.size {
			return e.cached, e.loadErr
		}
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return nil, err
	}
	e.cached, e.loadErr = Parse(data)
	e.mtime, e.size = st.ModTime(), st.Size()
	return e.cached, e.loadErr
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
		if e.approver == nil {
			return fmt.Errorf("denied by policy: %s (approval required but no approver available)", d.Reason)
		}
		if e.approver.Approve(req, time.Duration(p.AskTimeoutSeconds)*time.Second) {
			return nil
		}
		return fmt.Errorf("denied by policy: %s (approval not granted)", d.Reason)
	}
	return fmt.Errorf("denied by policy: unknown effect %q", d.Effect)
}
