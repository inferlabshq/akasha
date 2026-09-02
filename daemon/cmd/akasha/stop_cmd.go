package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
		// A supervisor that will restart the process has to be told first, or
		// the stop below is a restart wearing a success message.
		//
		// Only when this invocation is aimed at the DEFAULT daemon. The plist
		// and unit paths are fixed, so consulting them for a caller who named
		// another --socket/--db would stop a daemon they did not ask about —
		// which is how a test of one vault takes down the machine's real one.
		targeted := cmd.Root().PersistentFlags().Changed("socket") ||
			cmd.Root().PersistentFlags().Changed("db")
		if managed, what := stopServiceManager(); managed && !targeted {
			fmt.Fprintf(cmd.OutOrStdout(), "akasha: %s\n", what)
		}
		if !DaemonReachable(socketPath) {
			if !WaitUntilStopped(socketPath, stopWait) {
				return fmt.Errorf("the daemon is still answering %s.\n"+
					"  It is still holding the vault and still brokering credentials", socketPath)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "akasha: daemon stopped.")
			return nil
		}
		if _, err := daemonPost(socketPath, "/shutdown", map[string]interface{}{}); err != nil {
			if !DaemonReachable(socketPath) {
				fmt.Fprintln(cmd.OutOrStdout(), "akasha: no daemon is running.")
				return nil
			}
			return err
		}
		if !WaitUntilStopped(socketPath, stopWait) {
			msg := fmt.Sprintf("the daemon is still answering %s after %s.\n"+
				"  It is still holding the vault and still brokering credentials.", socketPath, stopWait)
			if hint := serviceManagerHint(); hint != "" {
				return fmt.Errorf("%s\n  %s", msg, hint)
			}
			return fmt.Errorf("%s\n  Find it with `lsof -i :7743` and stop it by hand", msg)
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

// WaitUntilStopped polls until the daemon stops answering AND stays stopped,
// or the deadline passes. It reports whether the daemon is gone.
//
// The second half is not pedantry. Measured on macOS against a launchd service
// with KeepAlive set -- which is what `akasha setup` installs:
//
//	akasha stop   ->  "akasha: daemon stopped."
//	6s later      ->  running again on a new pid, status ok, serving credentials
//
// The daemon really did exit; the socket really did stop answering; and launchd
// put it straight back. Reporting the gap as a stop is the same false claim
// this command was written to fix one layer down, so it has to outlast the
// restart rather than race it.
//
// settleWindow is how long "stopped" has to hold before it is believed.
//
// It is a backstop, not the mechanism. Racing a supervisor cannot be won by
// waiting longer: launchd throttles a respawn to about ten seconds, so a
// window short enough to be a pleasant `akasha stop` is always short enough to
// miss the restart. The supervisor is asked directly instead (see
// stopServiceManager); this only catches a manager we did not recognise.
const settleWindow = 3 * time.Second

func WaitUntilStopped(sock string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !DaemonReachable(sock) {
			return staysStopped(sock, settleWindow)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !DaemonReachable(sock) && staysStopped(sock, settleWindow)
}

// staysStopped reports whether the socket is still unanswered after the window
// -- i.e. nothing restarted the daemon behind us.
func staysStopped(sock string, window time.Duration) bool {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if DaemonReachable(sock) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
	return !DaemonReachable(sock)
}

// stopServiceManager stops the SERVICE when one owns this daemon, and reports
// whether it did.
//
// This has to come before /shutdown, and the reason is measured. `akasha setup`
// installs a launchd job with KeepAlive set. Asking the daemon to exit under
// that supervisor produced:
//
//	akasha stop   ->  "akasha: daemon stopped."
//	6s later      ->  running again on a new pid, serving credentials
//
// The process did exit. launchd put it back. A stop that a supervisor undoes is
// a restart, and reporting it as a stop is the false-success shape this command
// exists to remove. Waiting longer does not fix it either: launchd throttles
// respawns to roughly ten seconds, which is longer than anyone will wait for a
// stop to return.
//
// Unloading the job is also the CLEAN stop: launchctl and systemctl both signal
// the process, and the daemon traps SIGTERM to drain and checkpoint. Nothing is
// lost by not going through /shutdown here.
func stopServiceManager() (stopped bool, what string) {
	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "dev.akasha.daemon.plist")
		if _, err := os.Stat(plist); err != nil {
			return false, ""
		}
		// Errors are deliberately not fatal: the job may simply not be loaded,
		// which is indistinguishable here and means there is nothing to stop.
		exec.Command("launchctl", "unload", plist).Run()
		return true, "launchd service unloaded"
	case "linux":
		unit := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "akasha.service")
		if _, err := os.Stat(unit); err != nil {
			return false, ""
		}
		exec.Command("systemctl", "--user", "stop", "akasha").Run()
		return true, "systemd user service stopped"
	}
	return false, ""
}

// serviceManagerHint names the thing that would restart a daemon, so a failed
// stop points at the actual owner instead of leaving the reader to guess.
//
// Deliberately a HINT and not a detection: a plist or unit file on disk says a
// service was installed, not that it is loaded, and being wrong in the
// reassuring direction is what this whole area keeps getting caught doing. The
// message is phrased so it holds either way.
func serviceManagerHint() string {
	switch runtime.GOOS {
	case "darwin":
		p := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "dev.akasha.daemon.plist")
		if _, err := os.Stat(p); err == nil {
			return "launchd is configured to keep this daemon alive (KeepAlive in\n" +
				"  " + p + "), so stopping the process only makes it restart.\n" +
				"  Stop the service instead:  launchctl unload " + p
		}
	case "linux":
		p := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "akasha.service")
		if _, err := os.Stat(p); err == nil {
			return "a systemd user unit is installed, and it may be configured to restart\n" +
				"  the daemon. Stop the service instead:  systemctl --user stop akasha"
		}
	}
	return ""
}
