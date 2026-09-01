package assume

import (
	"fmt"
	"os"
	"time"
)

// A materialized credential is plaintext on disk, and until now nothing bounded
// how long one could live.
//
// `ttl_seconds` is an ADVERTISED parameter of the MCP vault_assume tool, so the
// caller choosing it is routinely the model. Write substituted a default only
// when the value was non-positive, which means a request for 999999999 seconds
// was honoured verbatim: a plaintext credential file stamped with an mtime in
// 2057, that SweepExpired — which removes a file only once its mtime is in the
// past — would never reclaim for the life of the machine.
//
// That is not merely a missing limit. docs/THREATMODEL.md promises "short-lived,
// audited access", and until this ceiling existed the agent decided how short.
//
// The ceiling is asymmetric on isHuman, which is already the boundary the daemon
// uses for its two most privileged paths: it is key-backed against a reserved
// identity that `akasha agent create` cannot mint, so it is not a new trust axis.
// An agent that wants a credential for longer than an hour is asking for exactly
// what `akasha exec` and `akasha run` exist to supervise.
const (
	// AgentTTLCeiling bounds a caller that is not the human CLI.
	AgentTTLCeiling = time.Hour
	// HumanTTLCeiling bounds the human CLI. 24h matches `akasha exec`'s
	// existing default, which is deliberate (exec.go:52-60: a credential must
	// outlive a SIGKILL of the supervisor), so nothing that works today breaks.
	HumanTTLCeiling = 24 * time.Hour
)

// MaxTTLEnv raises or lowers the machine's ceiling. Env rather than a policy
// matcher or a request field, and for the reason that decides every knob in this
// package: a request field is something the agent can set, and a policy matcher
// would put a lifetime VALUE inside an engine whose Decision deliberately
// carries no payload. This is an operator's machine setting, set where the
// daemon is started — the same shape as the audit log's retention bounds.
const MaxTTLEnv = "AKASHA_MAX_SESSION_TTL"

// Caller is the context a ceiling depends on. Both fields are established by the
// daemon from the key that authenticated the request; neither is anything the
// caller can assert in a body.
type Caller struct {
	// Human is true for the local CLI acting as the person.
	Human bool
	// RunDeadline, when non-zero, is when the supervised run this caller
	// belongs to ends.
	RunDeadline time.Time
}

// Grant is what a caller actually got, and why.
//
// Reason is non-empty exactly when the request was shortened. A SILENT clamp
// would reproduce the failure documented at addRunForm: a caller that believes
// it holds a credential it does not. Here it would be worse than believing —
// the file would really vanish early, mid-task, with nothing having said so.
type Grant struct {
	TTL       time.Duration
	Requested time.Duration
	Ceiling   time.Duration
	Reason    string
}

// Clamped reports whether the granted TTL is shorter than the request.
func (g Grant) Clamped() bool { return g.Reason != "" }

// MachineMaxTTL is the ceiling for this machine: HumanTTLCeiling unless an
// operator has said otherwise. An unparseable or non-positive value is IGNORED
// rather than treated as zero — a typo in an env var must not silently make
// every credential expire immediately, which reads as the product being broken.
func MachineMaxTTL() time.Duration {
	v := os.Getenv(MaxTTLEnv)
	if v == "" {
		return HumanTTLCeiling
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return HumanTTLCeiling
	}
	return d
}

// ClampTTL resolves the TTL a request actually gets.
//
// Order matters: the default is applied FIRST, then the ceiling. Doing it the
// other way lets a clamp land on zero and then be re-defaulted back up by
// Write's own `ttl <= 0` branch — the ceiling silently undone by the fallback
// that was meant to be harmless.
func ClampTTL(requested time.Duration, c Caller, now time.Time) Grant {
	g := Grant{Requested: requested, TTL: requested}
	if g.TTL <= 0 {
		g.TTL = DefaultTTL
	}

	machine := MachineMaxTTL()
	g.Ceiling = machine
	reason := fmt.Sprintf("this machine caps a session credential at %s (raise it with %s)", machine, MaxTTLEnv)

	// An agent gets the lower of the machine ceiling and the agent ceiling, so
	// raising the machine ceiling for a long human build does not hand the same
	// length to every model on the box.
	if !c.Human && AgentTTLCeiling < g.Ceiling {
		g.Ceiling = AgentTTLCeiling
		reason = fmt.Sprintf("an agent may hold a materialized credential for at most %s; "+
			"for longer work use `akasha run` or `akasha exec`, which supervise it", AgentTTLCeiling)
	}

	// A credential file must not outlive the run that asked for it. Today it
	// can: the run's key is revoked when the run ends, but the plaintext file it
	// materialized is governed only by its own mtime, so a 10-minute run could
	// leave an 8-hour credential behind it.
	if !c.RunDeadline.IsZero() {
		if left := c.RunDeadline.Sub(now); left < g.Ceiling {
			g.Ceiling = left
			reason = "a credential cannot outlive the run that assumed it"
		}
	}

	if g.TTL > g.Ceiling {
		g.TTL = g.Ceiling
		g.Reason = reason
	}
	return g
}
