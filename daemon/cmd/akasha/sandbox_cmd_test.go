package main

import (
	"strings"
	"testing"
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
