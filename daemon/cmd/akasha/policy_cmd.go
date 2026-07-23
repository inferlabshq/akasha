package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/internal/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Show the local retrieval policy (~/.akasha/policy.yaml)",
	Long: `Rules evaluated by the daemon before any secret reaches an agent —
on /retrieve, /assume, the credential helper, and /grant. First match wins;
effects are allow, deny, or ask (interactive approval, fail-closed).
Edits take effect immediately, no daemon restart needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := policy.DefaultPath()
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			fmt.Printf("No policy file at %s — all operations are allowed.\n", path)
			fmt.Println("Create one with `akasha policy init`.")
			return nil
		}
		if err != nil {
			return err
		}
		p, perr := policy.Parse(data)
		fmt.Printf("Policy: %s\n\n%s\n", path, data)
		if perr != nil {
			fmt.Printf("⚠  INVALID — the daemon is denying ALL operations until this parses: %v\n", perr)
			return nil
		}
		fmt.Printf("Valid: %d rule(s), default %s, ask timeout %ds.\n",
			len(p.Rules), p.Default, p.AskTimeoutSeconds)
		return nil
	},
}

var policyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a commented starter policy.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := policy.DefaultPath()
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists — edit it directly", path)
		}
		if err := os.MkdirAll(defaultDataDir(), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(starterPolicy), 0600); err != nil {
			return err
		}
		fmt.Printf("Wrote %s — active immediately, edit freely.\n", path)
		fmt.Println("Validate after editing with `akasha policy validate`.")
		return nil
	},
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check that policy.yaml parses (a broken file denies everything)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := policy.DefaultPath()
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			fmt.Printf("No policy file at %s — nothing to validate (all operations allowed).\n", path)
			return nil
		}
		if err != nil {
			return err
		}
		p, err := policy.Parse(data)
		if err != nil {
			return fmt.Errorf("INVALID (daemon denies all operations until fixed): %w", err)
		}
		fmt.Printf("✓ valid — %d rule(s), default %s.\n", len(p.Rules), p.Default)
		return nil
	},
}

const starterPolicy = `# Akasha retrieval policy — evaluated on every /retrieve, /assume, helper
# call and /grant, before any secret reaches an agent. First match wins.
# Effects: allow | deny | ask (native approval dialog; no answer = deny).
# Matchers (all optional, glob * ? supported, case-insensitive):
#   action: retrieve|assume|grant   agent:   tool:   provider:   instance:
#   category: (SSN, CreditCard, AWSAPIKey, Credential, ...)
#   min_risk: low|medium|high|critical   (matches that level and above)
# Edits apply immediately. Validate with: akasha policy validate
version: 1

# What happens when no rule matches: allow (advisory mode) or deny (lockdown).
default: allow

# Seconds an "ask" dialog waits before failing closed to deny.
ask_timeout_seconds: 60

rules:
  # Pause for human approval whenever an agent pulls critical data.
  - action: retrieve
    min_risk: critical
    effect: ask
    reason: critical data requires human approval

  # Assuming a working credential is always a big deal — ask.
  - action: assume
    effect: ask
    reason: credential handoff requires human approval

  # Example: block one agent from one provider entirely.
  # - action: assume
  #   agent: some-agent
  #   provider: aws
  #   effect: deny
  #   reason: this agent has no business in AWS
`

func init() {
	policyCmd.AddCommand(policyInitCmd, policyValidateCmd)
}
