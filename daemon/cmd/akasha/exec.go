package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/setup"
	"github.com/inferlabshq/akasha/daemon/internal/template"
)

var (
	execAssumes []string
	execTTL     int
)

var execCmd = &cobra.Command{
	Use:   "exec --assume provider:profile [--assume ...] -- command [args...]",
	Short: "Run a command with vaulted credentials injected into its environment",
	Long: `exec runs a command with a vaulted credential wired into its environment,
then cleans up when the command exits. Every use is recorded in the audit log.

If the provider template declares a broker mechanism (github/gitlab/git via a
git credential helper, aws via credential_process), exec wires the child so its
tooling resolves the secret through akasha PER OPERATION — the raw secret never
enters the environment:

  akasha exec --assume github:work -- git clone https://github.com/org/repo.git

Otherwise (ssh keys, or an arbitrary secret stored under the generic env:
provider) exec materializes a short-lived credential file / env vars for the
child:

  akasha put env:stripe STRIPE_API_KEY
  akasha exec --assume env:stripe -- ./charge.sh`,
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

	binary, _ := os.Executable()
	if binary == "" {
		binary = "akasha"
	}

	env := os.Environ()
	var cleanupPaths []string
	var ownDir string // holds rendered broker config for the child's lifetime
	cleanup := func() {
		for _, p := range cleanupPaths {
			os.Remove(p)
		}
		if ownDir != "" {
			os.RemoveAll(ownDir)
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

		// If the provider template declares a broker mechanism (git credential
		// helper, credential_process), apply THAT: the child's tooling resolves
		// the credential through `akasha helper` per operation, so the raw secret
		// never enters the environment. This is the codeable "assume and act"
		// path — e.g. `akasha exec --assume github:x -- git clone …`.
		if tpl := template.Get(provider); tpl != nil && tpl.Agent != nil {
			if ownDir == "" {
				d, err := os.MkdirTemp("", "akasha-exec-")
				if err != nil {
					return fmt.Errorf("assume %s: %w", a, err)
				}
				ownDir = d
			}
			ownEnv, err := setup.RenderOwnershipEnv(tpl, binary, ownDir, []string{profile})
			if err != nil {
				return fmt.Errorf("assume %s: wire broker: %w", a, err)
			}
			for k, v := range ownEnv {
				env = upsertEnv(env, k, v)
			}
			continue
		}

		// Otherwise materialize the credential (a session file for ssh, env vars
		// for the generic env: provider) via assume.
		resp, err := daemonPost(socketPath, "/assume", map[string]interface{}{
			"provider":    provider,
			"profile":     profile,
			"ttl_seconds": ttl,
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
				env = upsertEnv(env, k, s)
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

// upsertEnv sets key=val in env, replacing an existing entry for key rather than
// appending a duplicate. This matters when the child runs inside an already-owned
// agent session: the parent env may already carry GIT_CONFIG_GLOBAL (or an AWS
// config var) from `akasha setup`, and the broker/credential we're wiring must
// win. A duplicate would leave resolution to platform getenv semantics (glibc and
// macOS return the first match, so the parent's stale value could shadow ours);
// overwriting in place makes exec deterministic across platforms.
func upsertEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}
