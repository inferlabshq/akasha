package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/policy"
)

// captureStdout runs fn and returns whatever it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func parsePolicy(t *testing.T, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The pre-0.1.0-alpha.3 broker exception is dead weight that reads like a
// working permission. It must be called out on every validate until removed.
func TestWarnStaleHelperRule(t *testing.T) {
	p := parsePolicy(t, `
rules:
  - action: retrieve
    tool: akasha_helper
    effect: allow
  - action: retrieve
    effect: deny
`)
	out := captureStdout(t, func() { warnStaleHelperRule(p) })
	if !strings.Contains(out, "obsolete") || !strings.Contains(out, "akasha_helper") {
		t.Fatalf("stale rule not reported:\n%s", out)
	}

	// A policy without it stays quiet.
	clean := parsePolicy(t, "rules:\n  - {action: retrieve, effect: deny}\n")
	if out := captureStdout(t, func() { warnStaleHelperRule(clean) }); out != "" {
		t.Fatalf("clean policy should produce no warning, got:\n%s", out)
	}
}

// Allow rules keyed on a caller-asserted identity now grant only to key-holding
// callers. That is a silent behaviour change for anyone relying on one, so
// validate has to name them.
func TestWarnAdvisoryAllowRules(t *testing.T) {
	p := parsePolicy(t, `
rules:
  - action: retrieve
    agent: claude
    effect: allow
  - action: retrieve
    tool: my_tool
    effect: allow
`)
	out := captureStdout(t, func() { warnAdvisoryAllowRules(p) })
	if !strings.Contains(out, "[1 2]") {
		t.Fatalf("both advisory allow rules should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "agent key") {
		t.Fatalf("warning should explain the key requirement, got:\n%s", out)
	}
}

// Daemon-assigned identities are not forgeable, so rules written against them
// keep granting and must NOT be flagged — this is the guard against the
// warning turning into noise that trains people to ignore it.
func TestWarnAdvisoryAllowRulesSkipsServerAssigned(t *testing.T) {
	p := parsePolicy(t, `
rules:
  - {action: broker, agent: akasha-helper, effect: allow}
  - {action: list, agent: akasha-list, effect: allow}
  - {action: inspect, tool: akasha_inspect, effect: allow}
`)
	if out := captureStdout(t, func() { warnAdvisoryAllowRules(p) }); out != "" {
		t.Fatalf("server-assigned identities must not be flagged, got:\n%s", out)
	}
}

// Restrictive rules are unaffected by provenance, so they are not warned about.
func TestWarnAdvisoryAllowRulesIgnoresDenyAndAsk(t *testing.T) {
	p := parsePolicy(t, `
rules:
  - {action: retrieve, agent: experiment-bot, effect: deny}
  - {action: retrieve, tool: send_email, effect: ask}
`)
	if out := captureStdout(t, func() { warnAdvisoryAllowRules(p) }); out != "" {
		t.Fatalf("deny/ask rules must not be flagged, got:\n%s", out)
	}
}
