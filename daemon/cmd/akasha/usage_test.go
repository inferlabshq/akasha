package main

import (
	"bytes"
	"strings"
	"testing"
)

// GUARANTEE: a mistyped flag still gets the usage text that names the real one.
//
// `start` and `uninstall` suppress cobra's flag table after a failure, because
// their failures are multi-line vault-recovery instructions that the table
// pushes off a short terminal. Suppressing it on the COMMAND suppresses it for
// flag-parse errors too — those are raised before RunE ever runs — so
// `akasha start --no-such-flag` answered with a single bare "unknown flag" line
// and no list to correct it against, while every other akasha command still
// printed one. The suppression belongs inside RunE, where only the errors it
// was written for can reach it.
func TestFlagErrorsStillPrintUsage(t *testing.T) {
	for _, name := range []string{"start", "uninstall", "logs"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			rootCmd.SetOut(&out)
			rootCmd.SetErr(&out)
			rootCmd.SetArgs([]string{name, "--no-such-flag"})
			t.Cleanup(func() {
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				rootCmd.SetArgs(nil)
			})

			// Parsing fails before RunE, so nothing here opens a vault or
			// starts a daemon.
			if err := rootCmd.Execute(); err == nil {
				t.Fatal("an unknown flag must be an error")
			}
			if !strings.Contains(out.String(), "Usage:") {
				t.Fatalf("no usage printed for an unknown flag, only:\n%s", out.String())
			}
		})
	}
}
