package main

import (
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/policy"
)

// coverageOnly keeps the plan block and drops the argv. The failure that
// matters is the silent one: returning "" for a Linux profile would print
// nothing where the coverage table should be, which reads as "nothing is
// covered" — the exact ambiguity this whole table exists to remove.
func TestCoverageOnlyKeepsThePlanAndDropsTheArgv(t *testing.T) {
	profile := strings.Join([]string{
		"# What this profile does with each rule.",
		"#   tmpfs       /home/dev/.aws +remount-ro",
		"#",
		"# NOT MASKED (1).",
		"#   other-os    /Library/Keychains",
		"#              a darwin path",
		"",
		"/usr/bin/bwrap \\",
		"  --dev-bind \\",
		"  / \\",
	}, "\n")

	got := coverageOnly(profile)
	for _, want := range []string{"NOT MASKED (1)", "/home/dev/.aws", "/Library/Keychains"} {
		if !strings.Contains(got, want) {
			t.Errorf("the coverage table lost %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "bwrap") || strings.Contains(got, "--dev-bind") {
		t.Errorf("the launcher argv leaked into the coverage table:\n%s", got)
	}
}

// An SBPL profile has no plan block. Printing nothing would be indistinguishable
// from a profile that covers nothing, so it must say which case it is.
func TestCoverageOnlySaysSoWhenThereIsNoTable(t *testing.T) {
	got := coverageOnly("(version 1)\n(allow default)\n")
	if got == "" || !strings.Contains(got, "no coverage table") {
		t.Errorf("an empty coverage table must explain itself, got %q", got)
	}
}

// `akasha sandbox` is a parent with no body, so a bare invocation and a typo'd
// subcommand must both be refused rather than exiting 0 having done nothing.
func TestSandboxRequiresASubcommand(t *testing.T) {
	if sandboxCmd.RunE == nil && sandboxCmd.Run == nil {
		t.Fatal("`akasha sandbox` has no body and no guard — it would exit 0 silently")
	}
	if err := sandboxCmd.RunE(sandboxCmd, nil); err == nil {
		t.Error("`akasha sandbox` with no subcommand should be an error")
	}
	if err := sandboxCmd.RunE(sandboxCmd, []string{"doctr"}); err == nil {
		t.Error("`akasha sandbox doctr` should be refused, not silently accepted")
	}
	if !hasSubcommand(t, "doctor") {
		t.Error("`akasha sandbox doctor` is not registered")
	}
}

func hasSubcommand(t *testing.T, name string) bool {
	t.Helper()
	for _, c := range sandboxCmd.Commands() {
		if c.Name() == name {
			return true
		}
	}
	return false
}

// The starter policy ships a LIVE rule now, not just commented examples, so it
// has to parse, validate and lint clean — a shipped default that warns on first
// use teaches people to ignore the linter.
func TestStarterPolicyIsValidAndLintClean(t *testing.T) {
	p, err := policy.Parse([]byte(starterPolicy))
	if err != nil {
		t.Fatalf("the starter policy does not parse: %v", err)
	}
	if problems := p.Lint(); len(problems) > 0 {
		t.Errorf("the starter policy lints with warnings:\n  %v", problems)
	}

	// And the rule that does the routing is actually present and live.
	var found bool
	for _, r := range p.Rules {
		if r.Action == "assume" && r.Caller == "agent" && r.Brokerable != nil && *r.Brokerable {
			found = true
			if r.Effect != policy.EffectDeny {
				t.Errorf("the brokerable rule has effect %q, want deny", r.Effect)
			}
		}
	}
	if !found {
		t.Error("the starter policy no longer carries the brokerable rule as a live rule")
	}
}
