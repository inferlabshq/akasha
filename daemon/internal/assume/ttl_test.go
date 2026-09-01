package assume

import (
	"strings"
	"testing"
	"time"
)

func TestClampTTL(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	agent := Caller{}
	human := Caller{Human: true}

	for _, c := range []struct {
		name      string
		requested time.Duration
		caller    Caller
		want      time.Duration
		clamped   bool
	}{
		// The case this exists for: ttl_seconds is an advertised MCP parameter,
		// so an agent could ask for ~31 years and get a plaintext credential
		// file the sweeper would never reclaim.
		{"agent asks for 31 years", 999999999 * time.Second, agent, AgentTTLCeiling, true},
		{"human asks for 31 years", 999999999 * time.Second, human, HumanTTLCeiling, true},

		// Nothing that works today may break.
		{"agent within ceiling", 30 * time.Minute, agent, 30 * time.Minute, false},
		{"human within ceiling", 12 * time.Hour, human, 12 * time.Hour, false},
		{"exec's 24h default still fits a human", 24 * time.Hour, human, 24 * time.Hour, false},

		// Unset means the default, and that is not a clamp.
		{"unset", 0, agent, DefaultTTL, false},
		{"negative", -5 * time.Second, human, DefaultTTL, false},

		// An agent asking for exactly the human ceiling is still an agent.
		{"agent asks for 24h", 24 * time.Hour, agent, AgentTTLCeiling, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := ClampTTL(c.requested, c.caller, now)
			if g.TTL != c.want {
				t.Errorf("TTL = %s, want %s", g.TTL, c.want)
			}
			if g.Clamped() != c.clamped {
				t.Errorf("Clamped() = %v, want %v (reason %q)", g.Clamped(), c.clamped, g.Reason)
			}
			if g.Clamped() && g.Reason == "" {
				t.Error("a clamp with no reason is exactly the silent shortening this must not do")
			}
		})
	}
}

// A credential must not outlive the run that assumed it. Today it can: the run's
// key is revoked when the run ends, but the plaintext file it materialized is
// governed only by its own mtime.
func TestClampTTLNeverOutlivesItsRun(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	inRun := Caller{RunDeadline: now.Add(10 * time.Minute)}

	if g := ClampTTL(time.Hour, inRun, now); g.TTL != 10*time.Minute {
		t.Errorf("TTL = %s, want the 10m left of the run", g.TTL)
	} else if !strings.Contains(g.Reason, "outlive") {
		t.Errorf("reason should name the run, got %q", g.Reason)
	}

	// A request that already fits is untouched.
	if g := ClampTTL(5*time.Minute, inRun, now); g.TTL != 5*time.Minute || g.Clamped() {
		t.Errorf("a request inside the run's remaining time was altered: %+v", g)
	}
}

// The ordering bug, guarded directly.
//
// If the ceiling were applied BEFORE the default, an expired run would clamp to
// zero or less and then be re-defaulted back up to DefaultTTL by the `ttl <= 0`
// fallback — the ceiling silently undone by the branch meant to be harmless, and
// a dead run handed an hour-long credential.
func TestExpiredRunDoesNotFallBackToTheDefault(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	expired := Caller{RunDeadline: now.Add(-time.Minute)}

	for _, requested := range []time.Duration{0, time.Hour} {
		g := ClampTTL(requested, expired, now)
		if g.TTL > 0 {
			t.Errorf("requested %s from an ended run and got %s — the caller would be handed a "+
				"live credential by a run that no longer exists", requested, g.TTL)
		}
	}
}

// The escape hatch raises the human ceiling without handing the same length to
// every model on the machine.
func TestMaxTTLEnvRaisesTheHumanCeilingOnly(t *testing.T) {
	now := time.Now()
	t.Setenv(MaxTTLEnv, "48h")

	if g := ClampTTL(48*time.Hour, Caller{Human: true}, now); g.TTL != 48*time.Hour {
		t.Errorf("the operator raised the ceiling to 48h but got %s", g.TTL)
	}
	if g := ClampTTL(48*time.Hour, Caller{}, now); g.TTL != AgentTTLCeiling {
		t.Errorf("raising the machine ceiling also raised the AGENT ceiling to %s; an operator "+
			"lengthening their own build must not lengthen every agent's credential", g.TTL)
	}
}

// Lowering it applies to everyone, including agents already below the agent
// ceiling — the env is the machine's maximum, not a human-only dial.
func TestMaxTTLEnvLowersForEveryone(t *testing.T) {
	now := time.Now()
	t.Setenv(MaxTTLEnv, "5m")

	for _, c := range []Caller{{Human: true}, {}} {
		if g := ClampTTL(time.Hour, c, now); g.TTL != 5*time.Minute {
			t.Errorf("caller %+v got %s, want the machine ceiling of 5m", c, g.TTL)
		}
	}
}

// A typo must not make every credential expire instantly — that reads as the
// product being broken, and an operator would reach for --no-sandbox's cousin.
func TestGarbageMaxTTLEnvIsIgnored(t *testing.T) {
	for _, bad := range []string{"soon", "24", "-1h", "0"} {
		t.Setenv(MaxTTLEnv, bad)
		if got := MachineMaxTTL(); got != HumanTTLCeiling {
			t.Errorf("%s=%q gave a ceiling of %s, want the default %s", MaxTTLEnv, bad, got, HumanTTLCeiling)
		}
	}
}

// Write is exported, so it must bound a caller that never consulted ClampTTL.
// handleAssume clamps with full context before calling it; this is the backstop
// for every other call site, present and future.
func TestWriteBackstopsAnUnclampedTTL(t *testing.T) {
	t.Setenv(MaxTTLEnv, "2h")
	dir := t.TempDir()
	SetSessionBase(dir)
	t.Cleanup(func() { SetSessionBase("") })

	res, err := Write("env", "backstop", map[string]string{"TOKEN": "x"}, 100*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(res.ExpiresAt); d > 2*time.Hour+time.Minute {
		t.Errorf("Write honoured an unclamped 100-day TTL (expires in %s); the backstop is what "+
			"stops a future call site reintroducing the unbounded case", d)
	}
}
