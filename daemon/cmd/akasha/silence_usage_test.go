package main

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// inheritedPreRun returns the PersistentPreRun cobra would actually run for c —
// the nearest one walking up the parents, which is how cobra resolves it.
func inheritedPreRun(c *cobra.Command) func(*cobra.Command, []string) {
	for p := c; p != nil; p = p.Parent() {
		if p.PersistentPreRun != nil {
			return p.PersistentPreRun
		}
	}
	return nil
}

func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, sub := range c.Commands() {
		walk(sub, fn)
	}
}

// SilenceUsage as each command was DECLARED, captured before any test can run
// one. Cobra flips the flag on the shared rootCmd tree during Execute, so
// reading it later would tell you what some earlier test did rather than what
// the command ships with.
var declaredSilence = map[string]bool{}

func init() {
	walk(rootCmd, func(c *cobra.Command) { declaredSilence[c.CommandPath()] = c.SilenceUsage })
}

// GUARANTEE: an error a command RAISES never arrives buried under the flag table.
//
// A Linux user's first `akasha start` fails on the credential store, and the
// answer is several lines of prerequisite and remedy. Cobra printed ~12 lines of
// flag help after it, so on a short terminal the last thing on screen was a list
// of flags — which makes an environment problem look like a typo. The same
// applied to "daemon not reachable" from `status`, and to the multi-line
// vault-recovery guards.
//
// A dozen commands had been silenced one at a time and about twenty had not,
// which is the state this checks is over: every command that can raise a runtime
// error inherits the suppression, including ones added later.
func TestRuntimeErrorsAreNotBuriedUnderUsage(t *testing.T) {
	var missing []string
	walk(rootCmd, func(c *cobra.Command) {
		if c.RunE == nil && c.Run == nil {
			return // a group like `akasha vault` only ever prints help
		}
		if declaredSilence[c.CommandPath()] {
			return // silenced on the command itself — the older of the two idioms
		}
		hook := inheritedPreRun(c)
		if hook == nil {
			missing = append(missing, c.CommandPath()+" (nothing silences it)")
			return
		}
		// Ask the hook what it does to THIS command, then put the flag back:
		// rootCmd is package state shared with every other test in here.
		was := c.SilenceUsage
		c.SilenceUsage = false
		hook(c, nil)
		got := c.SilenceUsage
		c.SilenceUsage = was
		if !got {
			missing = append(missing, c.CommandPath())
		}
	})
	if len(missing) > 0 {
		t.Fatalf("these commands still print the flag table after a runtime error, "+
			"pushing the real message off a short terminal:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// GUARANTEE: the suppression above does not reach the errors usage answers.
//
// Suppressing on the COMMAND catches flag-parse and argument errors too, because
// both are raised before RunE — so `akasha start --no-such-flag` came back as a
// single bare line with no list to correct it against. Hooking PersistentPreRun
// instead puts the suppression after cobra has validated flags and args, which
// is the only placement that separates the two kinds of error.
//
// Driven through a throwaway command rather than a real one so nothing here can
// open a vault, reach a daemon, or touch a keychain.
func TestSyntaxErrorsStillPrintUsage(t *testing.T) {
	probe := &cobra.Command{
		Use:   "silence-usage-probe",
		Args:  cobra.ExactArgs(1),
		Short: "test-only",
		RunE:  func(*cobra.Command, []string) error { return errors.New("boom") },
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	run := func(args ...string) string {
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		rootCmd.SetArgs(args)
		defer func() {
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
			rootCmd.SetArgs(nil)
			probe.SilenceUsage = false
		}()
		if err := rootCmd.Execute(); err == nil {
			t.Fatalf("%v must be an error", args)
		}
		return out.String()
	}

	for _, tc := range []struct {
		name     string
		args     []string
		wantHelp bool
	}{
		{"unknown flag", []string{"silence-usage-probe", "--no-such-flag"}, true},
		{"wrong arg count", []string{"silence-usage-probe"}, true},
		{"error from the command body", []string{"silence-usage-probe", "arg"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Contains(run(tc.args...), "Usage:")
			if got != tc.wantHelp {
				if tc.wantHelp {
					t.Fatal("no usage printed for a syntax error, so nothing names the right flag")
				}
				t.Fatal("the flag table was printed after a runtime error, burying it")
			}
		})
	}
}

// GUARANTEE: nothing re-declares the suppression on a COMMAND, where it lands
// on the wrong side of flag parsing.
//
// This is the hole the two tests above leave between them. The first one accepts
// a struct-level `SilenceUsage: true` as satisfying its guarantee — it does —
// and skips such commands; the second proves the placement is right, but drives
// a throwaway command that no real one shares. So twelve commands could declare
// it themselves, silence their own flag-parse errors, and pass both: `akasha put
// --no-such-flag` answered with a bare "unknown flag" and no list to correct it
// against, while `akasha list --no-such-flag` printed one.
//
// The field is set at package init, before cobra has parsed anything, so a
// command that carries it cannot distinguish a mistyped flag from an error its
// own body raised. PersistentPreRun on the root already covers every command,
// present and future, at the only point where that distinction exists — which
// makes any remaining declaration both redundant and the only way to lose the
// guarantee.
func TestNoCommandDeclaresSilenceUsageItself(t *testing.T) {
	var declared []string
	for path, silenced := range declaredSilence {
		if silenced {
			declared = append(declared, path)
		}
	}
	if len(declared) > 0 {
		sort.Strings(declared)
		t.Fatalf("these commands set SilenceUsage in their struct literal, which runs before "+
			"cobra parses flags and so swallows the usage text for a mistyped flag too. "+
			"The root PersistentPreRun already silences runtime errors for every command — "+
			"delete the field:\n  %s", strings.Join(declared, "\n  "))
	}
}
