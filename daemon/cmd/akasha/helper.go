package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/internal/template"
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

		// Source-backed providers are brokered: the daemon resolves the secret
		// live from the backend (1Password, Vault, …) on every helper call and
		// never stores it. Other providers come from the vault as before.
		var creds map[string]string
		var err error
		if len(tpl.Source) > 0 {
			creds, err = resolveBroker(provider, instance)
		} else {
			creds, err = resolveLabel(provider, instance, "on-demand helper")
		}
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

// resolveBroker asks the daemon to resolve a source-backed provider's credential
// live from its backend (1Password, Vault, …). The daemon does the trust check,
// runs the backend, and audits; the helper only receives the resolved fields, so
// the secret is fetched fresh on every call and never stored.
func resolveBroker(provider, instance string) (map[string]string, error) {
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

// resolveLabel fetches the "<provider>:<instance>" label (a map of credential
// field → vault token) and resolves each token through the daemon's audited
// /retrieve. Agent identity is taken from the session environment.
func resolveLabel(provider, instance, why string) (map[string]string, error) {
	resp, err := daemonGet(socketPath, fmt.Sprintf("/label/get?name=%s:%s", provider, instance))
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable (is `akasha start` running?): %w", err)
	}
	var outer struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(resp), &outer); err != nil || outer.Value == "" {
		return nil, fmt.Errorf("no vaulted credential %s:%s (run `akasha discover` or `akasha put`)", provider, instance)
	}
	var tokens map[string]string
	if err := json.Unmarshal([]byte(outer.Value), &tokens); err != nil {
		return nil, fmt.Errorf("malformed credential map for %s:%s", provider, instance)
	}

	agentID := os.Getenv("AKASHA_AGENT_ID")
	if agentID == "" {
		agentID = "cli"
	}
	task := fmt.Sprintf("%s for %s:%s", why, provider, instance)

	creds := make(map[string]string, len(tokens))
	for field, token := range tokens {
		r, err := daemonPost(socketPath, "/retrieve", map[string]interface{}{
			"token":           token,
			"agent_id":        agentID,
			"requesting_tool": "akasha_helper",
			"task":            task,
		})
		if err != nil {
			return nil, err
		}
		if errMsg, _ := r["error"].(string); errMsg != "" {
			return nil, fmt.Errorf("retrieve %s: %s", field, errMsg)
		}
		v, _ := r["value"].(string)
		creds[field] = v
	}
	return creds, nil
}
