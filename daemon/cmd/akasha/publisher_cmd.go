package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/publisher"
)

var publisherName string

// publisher commands manage the trust roots for signed plugins. Trusting a
// publisher once means every plugin that publisher signs is accepted — the
// marketplace model: an author (e.g. "openclaw") publishes a signed plugin, the
// user trusts that author's key once, and the plugin is auto-approved.
var publisherCmd = &cobra.Command{
	Use:     "publisher",
	Aliases: []string{"publishers"},
	Short:   "Manage trusted plugin publishers (signing keys)",
}

var publisherAddCmd = &cobra.Command{
	Use:   "add <id> <pubkey-or-.pub-file>",
	Short: "Trust a publisher's signing key",
	Long:  "After trusting a publisher, any plugin validly signed by them is auto-approved (no per-template approval). Verify the key out-of-band before trusting.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, keyArg := args[0], args[1]
		pubStr := keyArg
		if data, err := os.ReadFile(keyArg); err == nil {
			pubStr = string(data)
		}
		if err := publisher.Add(id, publisherName, pubStr); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Trusting publisher %q. Plugins they sign are now auto-approved.\n", id)
		return nil
	},
}

var publisherRemoveCmd = &cobra.Command{
	Use:     "remove <id>",
	Aliases: []string{"rm", "untrust"},
	Short:   "Stop trusting a publisher",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		removed, err := publisher.Remove(args[0])
		if err != nil {
			return err
		}
		if !removed {
			fmt.Fprintf(cmd.OutOrStdout(), "%q was not a trusted publisher.\n", args[0])
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed publisher %q. Their plugins now need explicit approval.\n", args[0])
		return nil
	},
}

var publisherListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusted publishers",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		trusted, err := publisher.Trusted()
		if err != nil {
			return err
		}
		if len(trusted) == 0 {
			fmt.Fprintln(w, "No trusted publishers. The official key is unprovisioned; add one with `akasha publisher add`.")
			return nil
		}
		ids := make([]string, 0, len(trusted))
		for id := range trusted {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		users, _ := publisher.LoadUser()
		for _, id := range ids {
			label := "user"
			name := ""
			if id == publisher.OfficialID {
				label = "official (embedded)"
			} else if p, ok := users[id]; ok && p.Name != "" {
				name = " — " + p.Name
			}
			fmt.Fprintf(w, "  %-20s [%s]%s\n", id, label, name)
		}
		return nil
	},
}

func init() {
	publisherAddCmd.Flags().StringVar(&publisherName, "name", "", "Human-readable publisher name")
	publisherCmd.AddCommand(publisherAddCmd, publisherRemoveCmd, publisherListCmd)
}
