package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/sandbox"
	"github.com/inferlabshq/akasha/daemon/internal/setup"
	"github.com/inferlabshq/akasha/daemon/internal/template"
)

var (
	runAssumes    []string
	runNoSandbox  bool
	runPrintProf  bool
	runTTL        int
	runAllowRead  []string
	runAllowWrite []string
)

var runCmd = &cobra.Command{
	Use:   "run <agent> [--assume provider:instance ...] -- command [args...]",
	Short: "Launch an agent in an OS sandbox with brokered credentials",
	Long: `run supervises an agent: it launches the command inside an OS sandbox where
the vault, the OS keychain and your plaintext credential files are unreachable,
under its own audited identity, with access to only the credentials you name.

  akasha run claude --assume github:work -- claude

What it changes relative to ` + "`akasha exec`" + `:

  exec wires ONE command you chose. run supervises an AGENT SESSION — a process
  that decides for itself what to execute — so the sandbox wraps the whole
  process tree it spawns.

  exec can fall back to materializing a credential. run never does: it brokers
  per operation, and the daemon refuses the raw paths outright for the run's
  identity, so this is enforced rather than merely wired.

  If the supervisor is killed, the run's credentials are revoked immediately
  rather than staying valid for a TTL.

What it does NOT do, stated plainly:

  It does not confine the network, so a compromised agent can still exfiltrate
  what it is allowed to broker. It does not fix prompt injection — the sandbox
  confines the secret, not the operation. And a process inside the sandbox can
  still read the plaintext of a credential it is permitted to use; "broker-only"
  means the secret is not materialized into the session and every use is
  audited, not that the value is unreachable from inside.`,
	Args: cobra.MinimumNArgs(2),
	RunE: runRun,
}

func runRun(cmd *cobra.Command, args []string) error {
	// pflag strips the first "--", so the separator's position is how we tell
	// `run build ls` (missing separator) from `run build -- ls`. Without this
	// check the former would silently launch `ls` as agent "build".
	if dash := cmd.ArgsLenAtDash(); dash != 1 {
		return fmt.Errorf("usage: akasha run <agent> [--assume p:i] -- command [args...]\n" +
			"(the `--` separator is required, and <agent> comes before it)")
	}
	name, argv := args[0], args[1:]

	// Refuse un-brokerable providers before touching the daemon, so the error
	// names the real problem instead of surfacing as a 403 later.
	for _, a := range runAssumes {
		provider, _, ok := strings.Cut(a, ":")
		if !ok || provider == "" {
			return fmt.Errorf("bad --assume %q: want provider:instance (e.g. github:work)", a)
		}
		if err := brokerable(provider); err != nil {
			return err
		}
	}

	// Check the sandbox FIRST — before minting an identity or rendering config,
	// so a host that cannot isolate fails without leaving anything behind.
	if !runNoSandbox {
		if err := sandbox.Available(); err != nil {
			return fmt.Errorf("%s", sandbox.Explain(err))
		}
	}

	binary, _ := os.Executable()
	if binary == "" {
		binary = "akasha"
	}

	runDir, err := os.MkdirTemp("/tmp", "akasha-run-")
	if err != nil {
		return fmt.Errorf("run dir: %w", err)
	}
	defer os.RemoveAll(runDir)

	// Ask the daemon to open the run: it mints the identity, opens the run's
	// private socket, and applies the capability profile to it.
	resp, err := daemonPost(socketPath, "/run/begin", map[string]interface{}{
		"name": name, "assume": runAssumes, "run_dir": runDir, "ttl_seconds": runTTL,
	})
	if err != nil {
		return fmt.Errorf("start run: %w", err)
	}
	if msg, _ := resp["error"].(string); msg != "" {
		return fmt.Errorf("start run: %s", msg)
	}
	runID, _ := resp["run_id"].(string)
	agentID, _ := resp["agent_id"].(string)
	runKey, _ := resp["key"].(string)
	runSock, _ := resp["socket"].(string)
	if runID == "" || runKey == "" || runSock == "" {
		return fmt.Errorf("start run: malformed daemon response")
	}
	defer daemonPost(socketPath, "/run/end", map[string]interface{}{"run_id": runID})

	// Hold the control connection. Its loss is what ends the run, so this is
	// the mechanism that makes killing the supervisor revoke the credentials.
	attachRun(runID)

	// Broker wiring: the child's tooling resolves through `akasha helper` per
	// operation against the RUN's socket.
	env := os.Environ()
	if len(runAssumes) > 0 {
		ownEnv, err := assembleRunBroker(runDir, binary)
		if err != nil {
			return err
		}
		for k, v := range ownEnv {
			env = upsertEnv(env, k, v)
		}
	}
	env = upsertEnv(env, "AKASHA_AGENT_ID", agentID)
	// This overwrite is NOT optional. Invoked from inside an agent session the
	// variable already holds that agent's key; inheriting it would hand the
	// sandboxed child the OUTER agent's full authority — the exact opposite of
	// the feature.
	env = upsertEnv(env, "AKASHA_AGENT_KEY", runKey)
	env = upsertEnv(env, "AKASHA_SOCKET", runSock)

	spec := sandbox.Surface(defaultDataDir(), runDir, runAllowRead, runAllowWrite).
		AllowSocketPath(runSock)

	if runPrintProf {
		profile, err := sandbox.Describe(spec)
		if err != nil {
			return err
		}
		fmt.Println(profile)
		return nil
	}

	child := exec.Command(argv[0], argv[1:]...)
	child.Env = env
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr

	if runNoSandbox {
		warnNoSandbox()
	} else {
		// Prove the profile is ENFORCED before launching the real agent.
		//
		// A generated profile that renders cleanly and is accepted by the
		// launcher can still enforce nothing — a mistyped mach service, a
		// subpath with a trailing slash, a bwrap flag the kernel ignored. All of
		// those look identical to success from here, and a sandbox you believe
		// in but that is not enforcing is worse than none, because it is the one
		// you stop checking.
		if err := sandbox.SelfTest(spec, binary); err != nil {
			return err
		}
		if err := sandbox.Wrap(spec, child); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "akasha run: agent %s · may broker: %s · sandbox: %s\n",
		agentID, grantSummary(), sandboxSummary())
	fmt.Fprintln(os.Stderr, "akasha run: NOT confined: network. A compromised agent can still exfiltrate.")

	if err := child.Start(); err != nil {
		return err
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigc {
			if child.Process != nil {
				child.Process.Signal(s)
			}
		}
	}()
	werr := child.Wait()
	signal.Stop(sigc)
	close(sigc)

	if exitErr, ok := werr.(*exec.ExitError); ok {
		// os.Exit runs no defers, so the run has to be ended and the run dir
		// removed here by hand.
		daemonPost(socketPath, "/run/end", map[string]interface{}{"run_id": runID})
		os.RemoveAll(runDir)
		os.Exit(exitErr.ExitCode())
	}
	return werr
}

// brokerable reports whether a provider can be served per-operation.
//
// The predicate is the presence of an agent.own block with a VENDING mechanism —
// deliberately NOT DeliversSecretEnv(). That looks like the right check and is
// not: github declares both an agent block and a `deliver: mode: env` block, so
// DeliversSecretEnv is true for the flagship provider and gating on it would
// refuse the very thing run exists to serve. `deliver:` modes are only reachable
// through /assume, which a run never calls.
func brokerable(provider string) error {
	tpl := template.Get(provider)
	switch {
	case tpl == nil:
		return fmt.Errorf("provider %q has no template, so its credential could only be delivered as raw\n"+
			"environment variables. akasha run brokers per operation and never materializes a secret.\n"+
			"If you accept raw delivery in your own shell: akasha exec --assume %s:<instance> -- ...", provider, provider)
	case tpl.Agent == nil || len(tpl.Agent.Own) == 0:
		return fmt.Errorf("provider %q declares no broker mechanism (no `agent.own` block), so akasha run\n"+
			"cannot wire it. Inspect it with: akasha template explain %s", provider, provider)
	case !tpl.Brokerable():
		return fmt.Errorf("provider %q only declares a decoy mechanism — it blocks the plaintext path but\n"+
			"vends nothing, so there is nothing for a sandboxed agent to broker", provider)
	}
	return nil
}

// assembleRunBroker renders the per-operation broker config into the run dir.
func assembleRunBroker(runDir, binary string) (map[string]string, error) {
	inputs := map[string]*setup.OwnInput{}
	var order []string
	for _, a := range runAssumes {
		provider, instance, _ := strings.Cut(a, ":")
		in := inputs[provider]
		if in == nil {
			tpl := template.Get(provider)
			in = &setup.OwnInput{Provider: provider, Own: tpl.Agent.Own}
			inputs[provider] = in
			order = append(order, provider)
		}
		in.Instances = append(in.Instances, instance)
	}
	list := make([]setup.OwnInput, 0, len(order))
	for _, p := range order {
		list = append(list, *inputs[p])
	}
	env, err := setup.AssembleOwnership(runDir, binary, list)
	if err != nil {
		return nil, fmt.Errorf("wire broker: %w", err)
	}
	return env, nil
}

// attachRun opens the control connection and leaves it held for the lifetime of
// this process. There is deliberately no way to close it early: the connection
// dropping is what tells the daemon to revoke the run's credentials, so the
// supervisor being killed must be indistinguishable from it exiting cleanly.
// Orderly teardown is /run/end; this is the backstop for every other ending.
func attachRun(runID string) {
	go func() {
		// daemonGet blocks until the daemon closes its side, which it does when
		// the run ends.
		daemonGet(socketPath, "/run/attach?run_id="+runID)
	}()
}

func grantSummary() string {
	if len(runAssumes) == 0 {
		return "(nothing)"
	}
	return strings.Join(runAssumes, ", ")
}

func sandboxSummary() string {
	if runNoSandbox {
		return "OFF (--no-sandbox)"
	}
	return "on"
}

func warnNoSandbox() {
	const bar = "────────────────────────────────────────────────────────────────────────"
	fmt.Fprintln(os.Stderr, bar)
	fmt.Fprintln(os.Stderr, "  akasha run --no-sandbox: THE AGENT IS NOT ISOLATED")
	fmt.Fprintln(os.Stderr, "  It can read your vault, your OS keychain, ~/.ssh and ~/.aws directly.")
	fmt.Fprintln(os.Stderr, "  The daemon's policy and audit still apply, but nothing stops the agent")
	fmt.Fprintln(os.Stderr, "  reaching a secret without asking.")
	fmt.Fprintln(os.Stderr, bar)
}
