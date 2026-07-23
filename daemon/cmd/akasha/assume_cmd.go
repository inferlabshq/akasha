package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var assumeTTL int

// assumeCmd is the generic, template-driven shell assume: the daemon renders
// the credential through the provider template's deliver modes (file-tier
// where the template declares one — e.g. AWS gets a TTL-swept RAM-disk
// credentials file, never raw keys in the shell) and this command just prints
// the resulting export lines. No provider names appear here; `akasha assume
// datadog:default` works the moment a datadog template exists.
var assumeCmd = &cobra.Command{
	Use:   "assume <provider:profile>",
	Short: "Assume a vaulted credential into the current shell",
	Long: `Assumes a vaulted credential and prints shell export commands. The
credential is materialized by the provider's template (a short-lived file on
RAM-backed storage where the template supports it). Pipe to eval:

  eval $(akasha assume aws:default)
  eval $(akasha assume ssh:gitlab)

See what can be assumed with: akasha list`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, profile, ok := strings.Cut(args[0], ":")
		if !ok || provider == "" || profile == "" {
			return fmt.Errorf("expected <provider:profile>, e.g. aws:default (see `akasha list`)")
		}

		resp, err := daemonPost(socketPath, "/assume", map[string]interface{}{
			"provider":    provider,
			"profile":     profile,
			"ttl_seconds": assumeTTL,
			// A human at their own shell may receive raw env values (e.g.
			// eval $(akasha assume github)). The MCP agent tool never sets this.
			"allow_secret_env": true,
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
		fmt.Printf("# akasha: assuming %s:%s\n", provider, profile)
		for k, v := range env {
			fmt.Printf("export %s=%s\n", k, shellQuote(fmt.Sprint(v)))
		}
		if exp, _ := resp["expires_at"].(string); exp != "" {
			fmt.Fprintf(os.Stderr, "✓ %s:%s assumed (expires %s)\n", provider, profile, exp)
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
	assumeCmd.Flags().IntVar(&assumeTTL, "ttl", 0, "Seconds until the credential file is swept (default 3600)")
}
