package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var sessionTTL int

// sessionCmd is the generic, template-driven shell session: the daemon renders
// the credential through the provider template's deliver modes (file-tier
// where the template declares one — e.g. AWS gets a TTL-swept RAM-disk
// credentials file, never raw keys in the shell) and this command just prints
// the resulting export lines. No provider names appear here; `akasha session
// datadog:default` works the moment a datadog template exists.
//
// "session" says what you get: a session-scoped copy of the credential, alive
// until its TTL. The old name, "assume", is an AWS-ism for taking on a role
// and said nothing about lifetime, which is the one thing that distinguishes
// this from the broker. It stays as an alias for configs and habits.
var sessionCmd = &cobra.Command{
	Use:     "session <provider:profile>",
	Aliases: []string{"assume"},
	Short:   "Take a session on a vaulted credential in the current shell",
	Long: `Takes a session on a vaulted credential and prints shell export commands.
The credential is materialized by the provider's template (a short-lived file
on RAM-backed storage where the template supports it) for the session's TTL.
Pipe to eval:

  eval $(akasha session aws:default)
  eval $(akasha session ssh:gitlab)

For a single command, prefer the broker where the provider has one -- it keeps
nothing:  akasha exec --with aws:default -- <command>

See what a session can be taken on with: akasha list`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, profile, ok := strings.Cut(args[0], ":")
		if !ok || provider == "" || profile == "" {
			return fmt.Errorf("expected <provider:profile>, e.g. aws:default (see `akasha list`)")
		}

		// Still /assume, not /session, this release. An upgraded CLI must work
		// against a daemon that is still the previous build -- the two are the
		// same binary, but a running daemon keeps the one it started with -- and
		// /assume is the route both builds serve. Flip to /session once /assume
		// is the alias everywhere a user could be running.
		resp, err := daemonPost(socketPath, "/assume", map[string]interface{}{
			"provider":    provider,
			"profile":     profile,
			"ttl_seconds": sessionTTL,
		})
		if err != nil {
			return err
		}
		if errMsg, _ := resp["error"].(string); errMsg != "" {
			return fmt.Errorf("%s", errMsg)
		}

		env, _ := resp["env"].(map[string]interface{})
		if len(env) == 0 {
			return fmt.Errorf("template for %q delivers no environment", provider)
		}
		fmt.Printf("# akasha: session on %s:%s\n", provider, profile)
		for k, v := range env {
			fmt.Printf("export %s=%s\n", k, shellQuote(fmt.Sprint(v)))
		}
		if exp, _ := resp["expires_at"].(string); exp != "" {
			fmt.Fprintf(os.Stderr, "✓ %s:%s session open (expires %s)\n", provider, profile, exp)
		}
		return nil
	},
}

// shellQuote single-quotes a value for safe eval: a credential containing
// shell metacharacters (or a poisoned vault value) must never execute.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func init() {
	sessionCmd.Flags().IntVar(&sessionTTL, "ttl", 0, "Seconds until the credential file is swept (default 3600)")
}
