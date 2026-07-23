package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/inferlabshq/akasha/internal/setup"
	"github.com/inferlabshq/akasha/internal/vault"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agent API keys",
}

var agentCreateCmd = &cobra.Command{
	Use:   "create <agent-id>",
	Short: "Create an API key for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentID := args[0]
		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		keyID, plaintext, err := vlt.CreateAgentKey(agentID)
		if err != nil {
			return err
		}
		fmt.Printf("Agent key created for %q\n\n", agentID)
		fmt.Printf("  Key ID:  %s\n", keyID)
		fmt.Printf("  Key:     %s\n\n", plaintext)
		fmt.Println("Store this key securely — it will not be shown again.")
		fmt.Printf("\nUsage in Python SDK:\n")
		fmt.Printf("  vault = Akasha(agent_id=%q, api_key=%q)\n", agentID, plaintext)
		return nil
	},
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agent keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		keys, err := vlt.ListAgentKeys()
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			fmt.Println("No agent keys registered. Run `akasha agent create <agent-id>` first.")
			return nil
		}
		fmt.Printf("%-40s  %-24s  %-10s  %s\n", "KEY ID", "AGENT ID", "STATUS", "LAST USED")
		fmt.Println(strings.Repeat("-", 90))
		for _, k := range keys {
			status := "active"
			if k.Revoked {
				status = "revoked"
			}
			lastUsed := "never"
			if k.LastUsed != nil {
				lastUsed = k.LastUsed.Format("2006-01-02 15:04")
			}
			fmt.Printf("%-40s  %-24s  %-10s  %s\n", k.KeyID, k.AgentID, status, lastUsed)
		}
		return nil
	},
}

var agentResyncCmd = &cobra.Command{
	Use:   "resync [client]",
	Short: "Re-authorize an MCP client's agent key when it's out of sync with the vault",
	Long: `Repairs the "agent key not recognised" failure that happens when a client's
stored key no longer matches the vault (e.g. after the vault was rebuilt).

By default it RE-ADMITS the key already in the client's config — no key change,
so the running MCP server keeps working and the IDE does NOT need restarting.
This is safe to run unattended; an agent can run it itself after seeing the 401.

With no argument it repairs every configured client the vault no longer
recognises. Naming a client (claude, cursor, windsurf, codex) repairs just one.

  --rotate   Mint a brand-new key and rewrite the config instead of re-admitting
             the existing one. Use only if the current key may be compromised.
             This DOES require restarting the IDE.

A deliberately revoked key is never re-admitted (that would defeat revocation);
re-mint one explicitly with --rotate.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		binary, _ := os.Executable()
		if binary == "" {
			binary = "akasha"
		}

		// Build the target list.
		var targetIDs []string
		if len(args) == 1 {
			targetIDs = []string{args[0]}
		} else {
			for _, h := range setup.CheckAgents(vlt) {
				if h.Resyncable() {
					targetIDs = append(targetIDs, h.ID)
				} else if h.State == setup.HealthRevoked {
					fmt.Printf("• %s (%s): key was revoked — skipping. Re-mint with `akasha agent resync %s --rotate`.\n", h.Client, h.AgentID, h.ID)
				}
			}
			if len(targetIDs) == 0 {
				fmt.Println("All configured MCP clients are in sync with the vault.")
				return nil
			}
		}

		for _, id := range targetIDs {
			res, err := setup.ResyncClient(vlt, binary, id, resyncRotate)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", id, err)
				continue
			}
			if res.Rotated {
				fmt.Printf("  ✓ %s: new key issued and config rewritten — restart %s to pick it up.\n", res.Label, res.Label)
			} else {
				fmt.Printf("  ✓ %s: key re-authorized — no restart needed. Retry your last tool call.\n", res.Label)
			}
		}
		return nil
	},
}

var agentRevokeCmd = &cobra.Command{
	Use:   "revoke <key-id>",
	Short: "Revoke an agent API key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		if err := vlt.RevokeAgentKey(args[0]); err != nil {
			return err
		}
		fmt.Printf("Key %q revoked.\n", args[0])
		return nil
	},
}
