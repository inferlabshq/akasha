package main

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
)

// stopWait bounds how long `akasha stop` waits for the daemon to actually go.
// The daemon's own drain is bounded at 5s per half, so this has to be longer
// than that or a clean stop would be reported as a failed one.
const stopWait = 15 * time.Second

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running daemon",
	Long: `Stop the running daemon.

There was no way to do this. The only clean stop was a signal, so uninstall
asked systemd and could not tell whether it had worked — and on a machine
without a systemd user manager it reported a removal it had not performed while
the daemon went on serving credentials.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := daemonPost(socketPath, "/shutdown", map[string]interface{}{}); err != nil {
			if !DaemonReachable(socketPath) {
				fmt.Fprintln(cmd.OutOrStdout(), "akasha: no daemon is running.")
				return nil
			}
			return err
		}
		if !WaitUntilStopped(socketPath, stopWait) {
			return fmt.Errorf("the daemon accepted the stop but is still answering after %s.\n"+
				"  It is still holding the vault and still brokering credentials.\n"+
				"  Find it with `lsof -i :7743` and stop it by hand before uninstalling", stopWait)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "akasha: daemon stopped.")
		return nil
	},
}

// DaemonReachable reports whether anything is listening on the daemon socket.
//
// Dialling is the test, not the socket file existing: an unlinked socket with a
// live process behind it and a stale socket file with nothing behind it are
// both common, and they are opposite answers.
func DaemonReachable(sock string) bool {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// WaitUntilStopped polls until the daemon stops answering, or the deadline
// passes. It reports whether the daemon is gone.
func WaitUntilStopped(sock string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !DaemonReachable(sock) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !DaemonReachable(sock)
}
