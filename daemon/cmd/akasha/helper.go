package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

var helperTTL int

// helperCmd is the on-demand credential resolution hook that provider tooling
// calls back into — e.g. AWS's credential_process. It is wired up by the
// per-agent config stubs that setup generates, so every AWS CLI/SDK call
// inside an agent session resolves through the daemon: per-call audit, agent
// identity from the session environment, and nothing materialized on disk.
//
// Identity comes from AKASHA_AGENT_ID / AKASHA_AGENT_KEY in the environment
// (injected into agent harness sessions by setup). Without them the request
// is attributed to "cli" on an advisory basis, same as other CLI commands.
var helperCmd = &cobra.Command{
	Use:   "helper <provider> --instance <name>",
	Short: "Resolve a credential on demand (credential_process hook)",
	Long: `helper speaks a provider's native external-credential protocol on stdout.
It is not meant to be run by hand: provider tooling invokes it via the
generated agent config, e.g. for AWS:

  [profile default]
  credential_process = akasha helper aws --instance default

Line-protocol consumers (git credential helpers) append an action argument and
write a request on stdin:

  [credential]
      helper = !akasha helper github --instance default

Only the "get" action emits credentials; "store"/"erase" are acknowledged
silently (the vault is the source of truth — consumers never store into it).

Each emitting invocation is one audited retrieve against the daemon.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		provider := args[0]
		instance, _ := cmd.Flags().GetString("instance")

		// Credential-helper convention: a trailing action argument with the
		// request on stdin. Anything but "get" is a write-back attempt
		// (store/erase) — drain stdin and exit 0 without emitting; the vault
		// is never written through this path.
		if len(args) == 2 {
			io.Copy(io.Discard, os.Stdin)
			if args[1] != "get" {
				return nil
			}
		}

		tpl := template.Get(provider)
		if tpl == nil {
			return fmt.Errorf("no template for provider %q", provider)
		}

		// Every provider resolves through /resolve. The daemon decides how to
		// serve it — brokered live from a source backend (1Password, Vault, …)
		// or read from the vaulted label — so the helper never handles vault
		// tokens and never asserts its own identity. See resolveCreds.
		creds, err := resolveCreds(provider, instance)
		if err != nil {
			return err
		}
		out, err := template.ExecuteHelper(tpl, creds, time.Duration(helperTTL)*time.Second)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	helperCmd.Flags().String("instance", "default", "credential instance (e.g. AWS profile name)")
	helperCmd.Flags().IntVar(&helperTTL, "ttl", 900, "seconds the consumer may cache the result")
}

// resolveCreds asks the daemon for provider:instance. The daemon chooses the
// path — live from a source backend, or the vaulted label chain — does the
// trust check, applies policy, and audits; the helper only ever receives the
// resolved fields.
//
// This deliberately does NOT fetch the label and resolve field tokens itself.
// That older path had the helper POST /retrieve with `requesting_tool:
// "akasha_helper"`, a caller-supplied string the policy engine then matched on
// — so any process could claim the broker's identity and satisfy a rule written
// to permit it. The broker's identity must be established by which endpoint was
// called, never by what the caller writes in a request body.
func resolveCreds(provider, instance string) (map[string]string, error) {
	resp, err := daemonGet(socketPath, fmt.Sprintf("/resolve?provider=%s&instance=%s", provider, instance))
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable (is `akasha start` running?): %w", err)
	}
	var out struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		// The daemon returns a plain-text error body on failure (e.g. not trusted).
		return nil, fmt.Errorf("brokering %s:%s failed: %s", provider, instance, strings.TrimSpace(resp))
	}
	if len(out.Fields) == 0 {
		return nil, fmt.Errorf("no fields resolved for %s:%s", provider, instance)
	}
	return out.Fields, nil
}
