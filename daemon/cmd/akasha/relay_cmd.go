package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/egress"
)

// runRelayCmd is the inside half of `akasha run --network proxy`.
//
// Hidden because nobody types it: `akasha run` puts it in front of the agent's
// command so that, inside the network namespace, 127.0.0.1:PORT answers and
// pipes to the run's egress socket. See internal/egress for the picture.
//
// Its arguments are paths and a port — nothing secret — so they may travel on
// argv, unlike the self-test's plan.
var (
	relayListen   string
	relayUpstream string
)

var runRelayCmd = &cobra.Command{
	Use:    "run-relay --listen 127.0.0.1:PORT --upstream /path/egress.sock -- command [args...]",
	Short:  "Internal: loopback proxy relay for akasha run --network proxy",
	Hidden: true,
	Args:   cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if relayListen == "" || relayUpstream == "" {
			return fmt.Errorf("run-relay needs --listen and --upstream")
		}
		code, err := egress.RunRelay(relayListen, relayUpstream, args, os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			return err
		}
		if code != 0 {
			os.Exit(code)
		}
		return nil
	},
}

func init() {
	runRelayCmd.Flags().StringVar(&relayListen, "listen", "", "loopback address to answer on")
	runRelayCmd.Flags().StringVar(&relayUpstream, "upstream", "", "unix socket to pipe to")
}
