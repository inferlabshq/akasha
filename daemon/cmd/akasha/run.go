package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/egress"
	"github.com/inferlabshq/akasha/daemon/internal/sandbox"
	"github.com/inferlabshq/akasha/daemon/internal/setup"
	"github.com/inferlabshq/akasha/daemon/internal/template"
)

var (
	runAssumes    []string
	runNoNetwork  bool
	runNetwork    string
	runProxy      string
	runNoSandbox  bool
	runPrintProf  bool
	runTTL        int
	runAllowRead  []string
	runAllowWrite []string
)

var runCmd = &cobra.Command{
	Use:   "run <agent> [--with provider:instance ...] -- command [args...]",
	Short: "Launch an agent in an OS sandbox with brokered credentials",
	Long: `run supervises an agent: it launches the command inside an OS sandbox where
the vault, the OS keychain and your plaintext credential files are unreachable,
under its own audited identity, with access to only the credentials you name.

  akasha run claude --with github:work -- claude

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

  By default it does not confine the network, and says so on every launch: a
  compromised agent can still exfiltrate what it is allowed to broker, and can
  reach local services that are not sandboxed. --network none removes IP
  networking entirely — credentials still broker over the akasha socket; the
  internet, DNS and every local service are gone. --network proxy removes it
  the same way and gives back exactly one route: the proxy you name with
  --proxy, reached from inside as HTTPS_PROXY=http://127.0.0.1:<port>. akasha
  does not decide what that proxy passes — a CONNECT proxy sees hostnames, so
  an allow-list needs no TLS interception — and it does not stop the proxy
  reaching your own loopback if you let it. It does not fix prompt
  injection — the sandbox
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
		return fmt.Errorf("usage: akasha run <agent> [--with p:i] -- command [args...]\n" +
			"(the `--` separator is required, and <agent> comes before it)")
	}
	name, argv := args[0], args[1:]

	mode, proxyEndpoint, err := resolveNetworkMode(runNoNetwork, runNetwork, runProxy)
	if err != nil {
		return err
	}
	if mode == netProxy {
		// Before the daemon is touched: a run whose only route out is dead
		// should refuse with the proxy's name, not launch and fail its first
		// request from inside a namespace nobody can see into.
		if err := proxyEndpoint.Preflight(); err != nil {
			return fmt.Errorf("--network proxy: %w", err)
		}
	}

	// Refuse un-brokerable providers before touching the daemon, so the error
	// names the real problem instead of surfacing as a 403 later.
	for _, a := range runAssumes {
		provider, _, ok := strings.Cut(a, ":")
		if !ok || provider == "" {
			return fmt.Errorf("bad --with %q: want provider:instance (e.g. github:work)", a)
		}
		if err := brokerable(provider); err != nil {
			return err
		}
	}
	// …and refuse a label the vault does not hold, so the banner below cannot
	// announce a capability this run does not have.
	if err := assertAssumable(runAssumes); err != nil {
		return err
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

	// The proxy mode's plumbing, all of it in the run directory the sandbox
	// already lets the child into: a unix socket the supervisor forwards to the
	// operator's proxy, and a loopback port the relay inside will answer on.
	// The forwarder is up before the self-test so the door it opens is one the
	// self-test can prove dialable, like the broker socket.
	var egressSock string
	var proxyPort int
	if mode == netProxy {
		egressSock = filepath.Join(runDir, "egress.sock")
		ln, err := egress.ListenUnix(egressSock)
		if err != nil {
			return fmt.Errorf("--network proxy: %w", err)
		}
		fwdCtx, stopFwd := context.WithCancel(context.Background())
		defer stopFwd()
		go egress.Serve(fwdCtx, ln, proxyEndpoint.Dial,
			egress.OnceReporter(os.Stderr, "akasha run: proxy "+proxyEndpoint.String()+": "))
		proxyPort, err = egress.FreeLoopbackPort()
		if err != nil {
			return fmt.Errorf("--network proxy: no free loopback port: %w", err)
		}
		for k, v := range egress.ProxyEnv(proxyPort) {
			env = upsertEnv(env, k, v)
		}
	}

	// Mask the files these credentials actually came from, on top of the
	// well-known stores. See Spec.DenyingCredentialSources: the static list
	// missed fourteen of the sixteen locations akasha's own templates declare,
	// and masking all of them by name would break the project the agent is
	// working in. Provenance is the difference between the two.
	spec := sandbox.Surface(defaultDataDir(), runDir, runAllowRead, runAllowWrite).
		DenyingCredentialSources(credentialSources()).
		AllowSocketPath(runSock).
		AllowSocketPath(egressSock)
	// Set on the Spec rather than passed to the renderers, so --print-profile
	// and `sandbox doctor` show the same profile the run would actually get.
	spec.DenyNetwork = mode != netOff
	spec.ProxyPort = proxyPort

	if runPrintProf {
		profile, err := sandbox.Describe(spec)
		if err != nil {
			return err
		}
		fmt.Println(profile)
		return nil
	}

	if mode == netProxy {
		// Inside the namespace 127.0.0.1 is a different loopback, so the thing
		// that answers on the proxy port has to be inside too. The relay is the
		// agent's parent in there; it forwards signals and returns the agent's
		// exit code unchanged (internal/egress.RunRelay).
		argv = append([]string{binary, "run-relay",
			"--listen", "127.0.0.1:" + strconv.Itoa(proxyPort),
			"--upstream", egressSock, "--"}, argv...)
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
	// The banner tracks the profile rather than describing a default. It said
	// "NOT confined: network" unconditionally, which would have been a false
	// statement the moment --no-network existed — and on a security tool the
	// banner is the line a reader actually trusts.
	switch mode {
	case netNone:
		fmt.Fprintln(os.Stderr, "akasha run: network REMOVED — no internet, no DNS, and no local service. "+
			"Credentials still broker over the akasha socket.")
	case netProxy:
		fmt.Fprintf(os.Stderr, "akasha run: network via PROXY ONLY — %s is the one route out "+
			"(inside: HTTPS_PROXY=http://127.0.0.1:%d). No DNS, no direct internet, no local service.\n",
			proxyEndpoint, proxyPort)
		fmt.Fprintln(os.Stderr, "akasha run: what passes is that proxy's decision, including whether it "+
			"refuses your own loopback and private ranges. Credentials still broker over the akasha socket.")
	default:
		fmt.Fprintln(os.Stderr, "akasha run: NOT confined: network. A compromised agent can still exfiltrate, "+
			"and can reach local services that are not sandboxed. --network none removes it; "+
			"--network proxy leaves one route out.")
	}

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

// networkMode is what a run may reach on IP. Spelled as a flag value rather
// than a policy key for now: the policy key form in the design note waits on
// the per-template `network.hosts` declaration, which is public plugin-format
// surface and gets decided on its own.
type networkMode int

const (
	netOff   networkMode = iota // the host's network, banner says so
	netNone                     // IP removed; broker socket only
	netProxy                    // IP removed; one operator proxy given back
)

// resolveNetworkMode turns the three flags into one decision, refusing the
// combinations that would otherwise do something the person did not ask for.
func resolveNetworkMode(noNetwork bool, network, proxy string) (networkMode, egress.Endpoint, error) {
	var none egress.Endpoint
	if noNetwork {
		if network != "" && network != "off" && network != "none" {
			return 0, none, fmt.Errorf("--no-network and --network %s disagree; --no-network means --network none", network)
		}
		network = "none"
	}
	switch network {
	case "", "off":
		if proxy != "" {
			return 0, none, fmt.Errorf("--proxy was given but --network is %q; a proxy is only reachable under --network proxy", orDefault(network, "off"))
		}
		return netOff, none, nil
	case "none":
		if proxy != "" {
			return 0, none, fmt.Errorf("--proxy was given with --network none, which removes the network entirely; use --network proxy to keep that one route")
		}
		return netNone, none, nil
	case "proxy":
		if proxy == "" {
			return 0, none, fmt.Errorf("--network proxy needs --proxy: the one address the run may reach, e.g. --proxy 127.0.0.1:3128")
		}
		ep, err := egress.ParseEndpoint(proxy)
		if err != nil {
			return 0, none, err
		}
		return netProxy, ep, nil
	default:
		return 0, none, fmt.Errorf("--network %q: want off, none or proxy", network)
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
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
			"If you accept raw delivery in your own shell: akasha exec --with %s:<instance> -- ...", provider, provider)
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

// credentialSources asks the daemon which files this machine's credentials were
// discovered from.
//
// A failure is not fatal and is not silent-by-accident: the well-known stores
// are masked either way, and refusing to launch because an extra mask could not
// be computed would trade a working sandbox for a slightly wider one. The
// launch banner already prints what is NOT confined, and `akasha sandbox doctor`
// prints the full list that was applied, so the narrower surface is visible
// rather than assumed.
func credentialSources() []string {
	resp, err := daemonGet(socketPath, "/credential/sources")
	if err != nil {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		return nil
	}
	return out
}
