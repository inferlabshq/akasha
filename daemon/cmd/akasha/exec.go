package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	execAssumes []string
	execTTL     int
)

var execCmd = &cobra.Command{
	Use:   "exec --assume provider:profile [--assume ...] -- command [args...]",
	Short: "Run a command with vaulted credentials injected into its environment",
	Long: `exec assumes one or more vaulted credentials and launches a command with
them in its environment, then removes the credential files when the command
exits. Nothing is ever written to a config file in plaintext, and every assume
is recorded in the audit log.

This is how other MCP servers (and any process) draw secrets from Akasha
instead of hardcoding them. For example, in your MCP client config:

  "github": {
    "command": "akasha",
    "args": ["exec", "--assume", "github:default", "--", "github-mcp-server"]
  }

The GitHub token lives in the vault, is injected at launch, and the audit log
shows who assumed it — the MCP server itself never holds a plaintext secret.`,
	RunE: runExec,
}

func runExec(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command given; usage: akasha exec --assume aws:default -- mycmd [args]")
	}
	if len(execAssumes) == 0 {
		return fmt.Errorf("at least one --assume provider:profile is required")
	}

	// The credential file should outlive the command, but NOT be effectively
	// permanent: if we're SIGKILLed (cleanup can't run), the daemon's sweeper
	// must still reclaim the file. So we cap the TTL at 24h by default — long
	// enough for typical processes, short enough to be a real backstop. A
	// longer-running server can raise it with --ttl.
	ttl := execTTL
	if ttl <= 0 {
		ttl = 24 * 3600
	}

	env := os.Environ()
	var cleanupPaths []string
	cleanup := func() {
		for _, p := range cleanupPaths {
			os.Remove(p)
		}
	}
	// Runs on every *handled* exit, including the os.Exit path below where a
	// deferred func would NOT fire.
	defer cleanup()

	for _, a := range execAssumes {
		provider, profile, ok := strings.Cut(a, ":")
		if !ok || provider == "" || profile == "" {
			return fmt.Errorf("bad --assume %q: want provider:profile (e.g. aws:default)", a)
		}
		resp, err := daemonPost(socketPath, "/assume", map[string]interface{}{
			"provider":    provider,
			"profile":     profile,
			"ttl_seconds": ttl,
			// `akasha exec` runs a child on the human's own machine; the assumed
			// env (incl. raw values for env-delivered providers) is for that child.
			"allow_secret_env": true,
		})
		if err != nil {
			return fmt.Errorf("assume %s: %w", a, err)
		}
		if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
			return fmt.Errorf("assume %s: %s", a, errMsg)
		}
		envMap, _ := resp["env"].(map[string]interface{})
		if len(envMap) == 0 {
			return fmt.Errorf("assume %s: no credentials returned (is it vaulted?)", a)
		}
		for k, v := range envMap {
			if s, ok := v.(string); ok {
				env = append(env, k+"="+s)
			}
		}
		if p, ok := resp["path"].(string); ok && p != "" {
			cleanupPaths = append(cleanupPaths, p)
		}
	}

	child := exec.Command(args[0], args[1:]...)
	child.Env = env
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return err
	}

	// Forward termination signals to the child so it shuts down cleanly; its
	// exit then unblocks Wait() below and our cleanup runs. (A SIGKILL to *us*
	// can't be caught — that case is covered by the bounded TTL + sweeper.)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigc {
			if child.Process != nil {
				child.Process.Signal(s)
			}
		}
	}()

	err := child.Wait()
	signal.Stop(sigc)
	close(sigc)

	if exitErr, ok := err.(*exec.ExitError); ok {
		cleanup() // os.Exit skips defers — clean up explicitly
		os.Exit(exitErr.ExitCode())
	}
	return err
}
