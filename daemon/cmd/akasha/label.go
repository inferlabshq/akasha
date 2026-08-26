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

var (
	labelRmYes           bool
	labelRmDestroyEscrow bool
)

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
	Args: cobra.ExactArgs(1),
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

		// An escrow label whose original is not back on disk is the one removal
		// that DESTROYS data, and the generic advice below is wrong for it in
		// the most dangerous possible way: "re-create it from disk" points at
		// the stub. The daemon refuses this case outright; say so here, before
		// asking for a confirmation the daemon would not honour anyway.
		//
		// Both branches repeat what the DAEMON decided, and neither re-derives
		// it from the file: the daemon answers by comparing the escrowed bytes
		// with the disk, so "back on disk" below is a checked claim rather than
		// this command's guess.
		onlyCopy, _ := resp["escrow_only_copy"].(bool)
		escrowPath, _ := resp["escrow_path"].(string)

		fmt.Fprintf(w, "%s\n", name)
		switch {
		case onlyCopy:
			fmt.Fprintf(w, "  This name is the ONLY way back to the escrowed original of\n")
			fmt.Fprintf(w, "    %s\n", escrowPath)
			fmt.Fprintln(w, "  and what is on disk there is not that file. Removing this name")
			fmt.Fprintln(w, "  destroys it — no discover, backup or purge brings it back.")
			fmt.Fprintf(w, "  Put it back on disk first:  akasha restore %s\n", escrowPath)
		case escrowPath != "":
			// An escrow label whose file has been restored, byte for byte, as
			// the daemon verified above. Harmless to remove, but "re-run
			// `akasha discover`" is still the wrong way back — discovery does
			// not create escrow labels.
			fmt.Fprintf(w, "  %s is back on disk byte-for-byte, so this only forgets the escrow entry.\n", escrowPath)
			fmt.Fprintf(w, "  Escrow it again later with:  akasha protect %s\n", escrowPath)
		case len(others) > 0:
			fmt.Fprintf(w, "  Same credential is still reachable as: %s\n", strings.Join(others, ", "))
		default:
			fmt.Fprintln(w, "  This is its ONLY name. The credential stays in the vault but")
			fmt.Fprintln(w, "  nothing will be able to reach it — re-run `akasha discover` to")
			fmt.Fprintln(w, "  re-create it from disk, if the source still exists.")
		}

		if onlyCopy && !labelRmDestroyEscrow {
			return fmt.Errorf("refusing to remove %q: it is the only handle on the escrowed original of %s.\n"+
				"  Restore the file first, or — if you really want that file gone — say so by name:\n"+
				"    akasha label rm --destroy-escrowed-original %s", name, escrowPath, name)
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

		if _, err := daemonPost(socketPath, "/label/delete", map[string]interface{}{
			"name": name, "destroy_escrowed_original": labelRmDestroyEscrow,
		}); err != nil {
			return err
		}
		fmt.Fprintf(w, "✓ removed %s\n", name)
		return nil
	},
}

func init() {
	labelRmCmd.Flags().BoolVarP(&labelRmYes, "yes", "y", false, "Skip the confirmation prompt")
	labelRmCmd.Flags().BoolVar(&labelRmDestroyEscrow, "destroy-escrowed-original", false,
		"For an `escrow:` label whose file on disk is still a stub: remove it anyway, destroying the original")
	labelCmd.AddCommand(labelRmCmd)
}
