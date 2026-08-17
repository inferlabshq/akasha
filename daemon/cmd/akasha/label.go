package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var labelRmYes bool

var labelCmd = &cobra.Command{
	Use:   "label",
	Short: "Manage the names credentials are reachable under",
}

var labelRmCmd = &cobra.Command{
	Use:   "rm <provider:instance>",
	Short: "Remove a credential's name",
	Long: `Remove a name binding.

Discovery creates names; until now nothing removed them. A renamed SSH key, a
retired profile, or a typo'd ` + "`akasha put`" + ` left a name that could never be
cleaned up — and because a name anchors its credential against garbage
collection, the entry behind it stayed forever too.

This removes the NAME. The credential itself is not destroyed: if it was created
by discovery it becomes collectable on the next run, and if an agent stored it
the secret is left alone. Re-running discovery re-creates names for anything
still present on disk.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if !strings.Contains(name, ":") {
			return fmt.Errorf("expected provider:instance (e.g. ssh:gitlab), got %q", name)
		}
		w := cmd.OutOrStdout()

		// Preview via the delete endpoint itself. NOT /credential/retrieve: that endpoint
		// decrypts and returns the raw credential, so using it to build a
		// confirmation prompt would read the secret in order to ask whether to
		// forget its name.
		resp, err := daemonPost(socketPath, "/label/delete", map[string]interface{}{
			"name": name, "preview": true,
		})
		if err != nil {
			return err
		}
		var others []string
		if raw, ok := resp["also_named"].([]interface{}); ok {
			for _, v := range raw {
				if sname, ok := v.(string); ok {
					others = append(others, sname)
				}
			}
		}
		sort.Strings(others)

		fmt.Fprintf(w, "%s\n", name)
		if len(others) > 0 {
			fmt.Fprintf(w, "  Same credential is still reachable as: %s\n", strings.Join(others, ", "))
		} else {
			fmt.Fprintln(w, "  This is its ONLY name. The credential stays in the vault but")
			fmt.Fprintln(w, "  nothing will be able to reach it — re-run `akasha discover` to")
			fmt.Fprintln(w, "  re-create it from disk, if the source still exists.")
		}

		if !labelRmYes {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("refusing to remove a label non-interactively without --yes")
			}
			fmt.Fprint(w, "Remove this name? [y/N]: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if ans := strings.ToLower(strings.TrimSpace(line)); ans != "y" && ans != "yes" {
				fmt.Fprintln(w, "Nothing removed.")
				return nil
			}
		}

		if _, err := daemonPost(socketPath, "/label/delete", map[string]interface{}{"name": name}); err != nil {
			return err
		}
		fmt.Fprintf(w, "✓ removed %s\n", name)
		return nil
	},
}

func init() {
	labelRmCmd.Flags().BoolVarP(&labelRmYes, "yes", "y", false, "Skip the confirmation prompt")
	labelCmd.AddCommand(labelRmCmd)
}
