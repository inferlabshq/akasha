package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Neither of the two CLI behaviours added to stop a credential quietly changing
// hands had a test, which is how a third of them shipped broken: overwriting
// RunE unconditionally deleted `akasha policy`, the only way to read the active
// policy from the CLI.

// A parent with no body must refuse rather than print help and exit 0.
//
// `akasha vault bakcup` printed the vault help and exited 0. A human sees the
// help; a script sees success — and the command it failed to run is the one
// that protects against losing the vault key.
func TestParentCommandsRejectUnknownSubcommands(t *testing.T) {
	for _, parent := range []*cobra.Command{agentCmd, vaultCmd, labelCmd, templateCmd, publisherCmd, policyCmd} {
		name := parent.Name()

		// A name it does not know is an error, whatever else the parent does.
		if parent.Args != nil {
			if err := parent.Args(parent, []string{"definitely-not-a-subcommand"}); err == nil {
				t.Errorf("`akasha %s <typo>` was accepted — a mistyped subcommand must not look like success", name)
			} else if !strings.Contains(err.Error(), "unknown subcommand") {
				t.Errorf("`akasha %s <typo>` error should name the problem, got: %v", name, err)
			}
		} else if parent.RunE == nil {
			t.Errorf("`akasha %s` has neither a body nor an argument check, so a typo prints help and exits 0", name)
		}
	}
}

// …but a parent that already DOES something keeps doing it. policyCmd prints
// the active policy and there is no `policy show` to fall back on, so taking
// its body away removed the only way to read the policy at all — on a command
// both the README and getting-started tell people to run.
func TestParentCommandsWithABodyKeepIt(t *testing.T) {
	// Checking RunE != nil proves nothing: requireSubcommand SETS RunE, so the
	// field is populated either way. What distinguishes "kept its body" from
	// "had its body replaced by a refusal" is what running it does.
	if policyCmd.RunE == nil {
		t.Fatal("`akasha policy` has no body at all")
	}
	err := policyCmd.RunE(policyCmd, nil)
	if err != nil && strings.Contains(err.Error(), "needs a subcommand") {
		t.Fatal("`akasha policy` was replaced by a refusal: it prints the active policy, " +
			"there is no `policy show`, and both README and getting-started tell people to run it")
	}
	// And a bare invocation must still be allowed to reach that body.
	if policyCmd.Args != nil {
		if err := policyCmd.Args(policyCmd, nil); err != nil {
			t.Errorf("`akasha policy` with no arguments must still print the policy, got: %v", err)
		}
	}
}
