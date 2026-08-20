// Package setup implements the interactive first-run setup wizard.
package setup

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/inferlabshq/akasha/daemon/internal/clikey"
	"github.com/inferlabshq/akasha/daemon/internal/provision"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// Provider is a non-MCP agent that integrates via the Python SDK.
type Provider struct {
	ID    string
	Label string
}

// sdkAgents are configured by printing a code snippet (they need code changes).
var sdkAgents = []Provider{
	{ID: "ollama", Label: "Ollama / LM Studio (local models)"},
	{ID: "openai", Label: "OpenAI / GPT"},
	{ID: "langchain", Label: "LangChain"},
	{ID: "custom", Label: "Custom Python agent"},
}

// sdkAgentsFrom returns the SDK agents named in selected (empty if none).
func sdkAgentsFrom(selected []string) []Provider {
	var out []Provider
	for _, p := range sdkAgents {
		if contains(selected, p.ID) {
			out = append(out, p)
		}
	}
	return out
}

// AssumeYes makes setup answer its own prompts with the safe default, for
// unattended installs — devcontainers, provisioning scripts, CI. Set from
// `akasha setup --yes`.
//
// Deliberately NOT "accept everything". It approves only the SHIPPED provider
// bundle, never a user drop-in, and it cannot create a key backup because that
// needs a passphrase. See offerBundleTrust and offerBackup for why each choice
// is what it is.
var AssumeYes bool

// Run is the entry point for `akasha setup`.
func Run(dbPath, logPath, socketPath string, selected []string) error {
	fmt.Println("Akasha setup")
	fmt.Println()

	// Start / register the daemon.
	if err := ensureDaemon(socketPath, logPath, dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not register daemon service: %v\n", err)
		fmt.Println("  → Run `akasha start` manually before using Akasha.")
	}

	// Wait briefly for the daemon to accept connections.
	waitForDaemon(5 * time.Second)

	// Open vault to create agent keys.
	vlt, err := vault.Open(dbPath, vault.Options{})
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer vlt.Close()

	// Trust the bundled providers once, up front, so discovery and agent-session
	// ownership below can apply them. Subsequent or edited templates are gated
	// the same way and approved individually with `akasha template trust`.
	offerBundleTrust()

	// Discover and vault credentials — the aha moment.
	discoverAndVault(socketPath, dbPath)

	// Silent key backup so the vault is recoverable.
	offerBackup(vlt, dbPath)

	binary, _ := os.Executable()
	if binary == "" {
		binary = "akasha"
	}

	// ── Configure MCP IDEs ──
	// With no --providers, auto-detect every installed MCP client. With
	// --providers, honor the explicit selection (even if not detected).
	configureMCPClients(vlt, binary, selected)

	// ── SDK agents (Ollama, OpenAI, custom Python) ──
	// These need code changes, so only print snippets when explicitly asked.
	for _, p := range sdkAgentsFrom(selected) {
		_, key, err := vlt.CreateAgentKey(p.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ could not create agent key: %v\n", err)
			continue
		}
		fmt.Printf("\nSetting up %s...\n", p.Label)
		printSDKSnippet(p, key)
	}

	fmt.Printf("\nDone. Audit log: %s\n", logPath)
	return nil
}

// offerBundleTrust records one-time, hash-bound approval for the provider
// templates that need it (those that write credential files, set environment
// variables, own agent sessions, read files, or run a backend), so
// out-of-the-box `assume` works without a separate step. Trust stays explicit:
// the user sees what each provider will do and where it came from, and confirms
// once. Already-trusted or validly-signed providers are skipped, and a
// non-interactive run never auto-approves — it prints the command to run.
func offerBundleTrust() {
	store, err := trust.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ! trust store unreadable (%v) — provider approval skipped\n", err)
		return
	}
	var pending []*template.Template
	for _, t := range template.Providers() {
		if len(t.SensitiveCapabilities()) == 0 {
			continue // inert (e.g. on-demand helper only) — no approval needed
		}
		if ok, _ := store.Approved(t); ok {
			continue // already trusted or validly signed
		}
		pending = append(pending, t)
	}
	if len(pending) == 0 {
		return
	}

	fmt.Println("\nThese provider templates act on your machine (write credential files,")
	fmt.Println("set environment variables, own agent sessions). Review before trusting:")
	for _, t := range pending {
		fmt.Printf("  • %-10s %s\n", t.Name, t.Capabilities())
		fmt.Printf("    from %s\n", shorten(t.Origin()))
	}

	// --yes approves the SHIPPED bundle only.
	//
	// The distinction matters more than it looks. This list is built from every
	// loaded provider, which includes anything dropped in ~/.akasha/templates/ —
	// and a template that acts on your machine is exactly what the trust gate
	// exists to hold back. Auto-approving a user drop-in because someone asked
	// for an unattended install would turn "I don't want to answer prompts" into
	// "approve whatever is on disk", which is how a supply-chain hole gets
	// installed by a convenience flag. Shipped templates come from the bundle
	// the installer wrote; those are the ones --yes covers.
	if AssumeYes {
		shipped := template.ShippedDir()
		var auto, manual []*template.Template
		for _, t := range pending {
			if shipped != "" && strings.HasPrefix(t.Origin(), shipped) {
				auto = append(auto, t)
			} else {
				manual = append(manual, t)
			}
		}
		pending = auto
		for _, t := range manual {
			fmt.Printf("  ! %s is not part of the shipped bundle — approve it deliberately:\n", t.Name)
			fmt.Printf("      akasha template explain %s && akasha template trust %s\n", t.Name, t.Name)
		}
		if len(pending) == 0 {
			return
		}
		fmt.Println("  (--yes) trusting the shipped bundle")
	} else if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("Approve them when ready:  akasha template trust <name>")
		return
	} else {
		fmt.Print("Trust these bundled providers so agents can use them? [Y/n]: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if ans := strings.ToLower(strings.TrimSpace(line)); ans == "n" || ans == "no" {
			fmt.Println("  skipped — approve later with `akasha template trust <name>`")
			return
		}
	}

	n := 0
	for _, t := range pending {
		if err := store.Approve(t); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ could not approve %s: %v\n", t.Name, err)
			continue
		}
		n++
	}
	if err := store.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ could not save approvals: %v\n", err)
		return
	}
	fmt.Printf("  ✓ trusted %d bundled provider(s) — edits will require re-approval\n", n)
}

// configureMCPClients detects (or selects) MCP IDEs and writes each one's config.
func configureMCPClients(vlt *vault.Vault, binary string, selected []string) {
	// Owning an agent session's env is a high-trust effect, applied only for
	// templates the user has explicitly approved (hash-bound). A load error or
	// a missing approval means deny — never wire ownership silently.
	ts, terr := trust.Load()
	if terr != nil {
		fmt.Fprintf(os.Stderr, "  ! trust store unreadable (%v) — agent-session ownership disabled\n", terr)
	}
	trustedFn := func(t *template.Template) bool {
		if terr != nil || ts == nil {
			return false
		}
		ok, _ := ts.Approved(t)
		return ok
	}

	for _, c := range mcpClients {
		want := len(selected) == 0 && c.installed()
		if contains(selected, c.id) {
			want = true
		}
		if !want {
			continue
		}
		// Capture the key this client currently holds, so the new one REPLACES
		// it rather than joining it. Re-running setup used to mint a key and
		// leave the previous one valid forever — a machine set up three times
		// carried three working credentials per client, all indefinitely valid,
		// for agents that had long stopped using them.
		var supersededKey string
		if args, ok := c.readAkashaArgs(); ok {
			_, supersededKey, _ = agentIDAndKey(args)
		}

		_, key, err := vlt.CreateAgentKey(c.id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: agent key: %v\n", c.label, err)
			continue
		}
		fmt.Printf("\nSetting up %s...\n", c.label)
		if err := c.configure(binary, key); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ config: %v\n", err)
			fmt.Printf("  → Add manually — key: %s\n", key)
			continue
		}
		// Only after the new key is safely in the config.
		if supersededKey != "" && supersededKey != key {
			if err := vlt.RevokeAgentKeyByValue(supersededKey); err != nil {
				fmt.Fprintf(os.Stderr, "  ! could not retire the previous key: %v\n", err)
			}
		}
		fmt.Printf("  ✓ MCP config written to %s\n", c.cfgPath)
		fmt.Printf("  ✓ Agent identity: %s\n", c.id)

		// Env ownership: route this agent's sessions through the daemon by
		// default (generated config stubs + harness env injection).
		if t := c.envTargetFor(); t != nil {
			env, skipped, err := writeAgentDir(c.id, binary, trustedFn, func(provider string) []string {
				labels, _ := vlt.ListLabels(provider + ":")
				for i, l := range labels {
					labels[i] = strings.TrimPrefix(l, provider+":")
				}
				return labels
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ agent env: %v\n", err)
			} else {
				env["AKASHA_AGENT_KEY"] = key
				if err := injectAgentEnv(t, env); err != nil {
					fmt.Fprintf(os.Stderr, "  ! agent env: %v\n", err)
				} else {
					fmt.Printf("  ✓ Session env routed through akasha (%s)\n", shorten(expand(t.path)))
				}
			}
			if len(skipped) > 0 {
				sort.Strings(skipped)
				fmt.Printf("  ! Not yet trusted to manage agent sessions: %s\n", strings.Join(skipped, ", "))
				fmt.Printf("    Review what each would do, then approve:  akasha template explain <name> ; akasha template trust <name>\n")
			}
		}
		fmt.Printf("  → Restart %s\n", c.label)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ─── Discovery + backup (the aha moment) ──────────────────────────────────

// discoverAndVault scans the machine for credentials and vaults them via the
// running daemon, printing what it found. This is the immediate-value step.
func discoverAndVault(socketPath, dbPath string) {
	fmt.Println("Scanning for credentials...")
	found := 0
	p := provision.NewSocket(socketPath, "akasha-setup").WithKey(clikey.Load(clikey.Path(dbPath)))

	// ONE path for every provider. aws, ssh and git used to be scanned by
	// hand-written Go here, ahead of this loop; they are now ordinary templates
	// whose `discover` blocks declare every location they read. That is what
	// makes the shipped bundle honest — and what puts all credential-file
	// reading behind the same trust gate, since an unapproved template is not
	// run at all.
	failed := 0
	for _, f := range template.DiscoverUser(trust.ApprovedFunc()) {
		if err := p.VaultFinding(f.Provider, f.Instance, f.Fields, f.Source); err != nil {
			// Never silent. Counting only successes and then reporting "no
			// credentials found" blamed discovery for a vaulting failure, so a
			// broken daemon looked like a clean machine and setup finished with
			// an empty vault and no error.
			fmt.Printf("  ✗ %s:%s: %v\n", f.Provider, f.Instance, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s %s (%s)   → vaulted\n", f.Provider, f.Instance, f.Source)
		found++
	}

	switch {
	case failed > 0:
		fmt.Printf("  %d credential(s) were found but could NOT be vaulted — see above.\n", failed)
	case found == 0:
		fmt.Println("  (no credentials found — add some later with `akasha discover aws`)")
	}

	// GC credential chains orphaned by a previous run so re-running setup
	// doesn't grow the vault unbounded.
	p.PurgeOrphans()
	fmt.Println()
}

// offerBackup creates a key backup protected by a passphrase only the user
// knows. It deliberately does NOT auto-write to a cloud-synced folder under a
// machine-derivable passphrase: a recovery backup that leaves the machine must
// be encrypted with a secret an attacker can't reconstruct, or obtaining the
// file would mean obtaining the vault. Interactive sessions are prompted for a
// passphrase; non-interactive ones get instructions.
func offerBackup(vlt *vault.Vault, dbPath string) {
	home, _ := os.UserHomeDir()
	dest := filepath.Join(home, "akasha-backup.akb")

	// --yes cannot make a backup: it needs a passphrase, and the only ways to
	// supply one unattended are an env var or a file — both of which put the
	// key to your recovery net next to the thing it is meant to recover.
	//
	// So it is skipped, LOUDLY. This is the one prompt whose absence has a
	// delayed cost: the backup is what recovers a vault when the OS keychain
	// entry is lost or its ACL breaks, and by the time you need it, it is too
	// late to make one.
	if AssumeYes {
		fmt.Println()
		fmt.Println("  ⚠ NO KEY BACKUP WAS CREATED (--yes cannot hold a passphrase).")
		fmt.Println("    Without one, losing your OS keychain entry means losing every")
		fmt.Println("    agent-stored secret — there is no other copy. Make one now:")
		fmt.Printf("        akasha vault backup %s\n", shorten(dest))
		fmt.Println()
		return
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("Key backup: run `akasha vault backup` to create a passphrase-")
		fmt.Println("protected recovery file (needed if your keychain is ever lost).")
		return
	}

	fmt.Println("Create an encrypted key backup now? It protects against losing your")
	fmt.Println("OS keychain entry. Enter a passphrase (or leave blank to skip):")
	fmt.Print("  passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil || len(pass) == 0 {
		fmt.Println("  skipped — run `akasha vault backup` later.")
		return
	}
	if err := vlt.BackupKey(dest, pass); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: key backup failed: %v\n", err)
		return
	}
	fmt.Printf("  ✓ backup saved to %s\n", shorten(dest))
	fmt.Println("  Store this file + passphrase somewhere safe (1Password, a USB drive).")
}

func shorten(p string) string {
	home, _ := os.UserHomeDir()
	if strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}

// ─── Daemon management ────────────────────────────────────────────────────

func ensureDaemon(socketPath, logPath, dbPath string) error {
	// Check if daemon is already reachable.
	if isDaemonRunning() {
		fmt.Println("  ✓ Daemon already running")
		return nil
	}

	switch runtime.GOOS {
	case "darwin":
		return registerLaunchd(dbPath, logPath, socketPath)
	case "linux":
		return registerSystemd(dbPath, logPath, socketPath)
	default:
		fmt.Println("  → Start the daemon manually: akasha start")
		return nil
	}
}

func isDaemonRunning() bool {
	resp, err := httpGet("http://127.0.0.1:7743/health")
	return err == nil && strings.Contains(resp, "ok")
}

func waitForDaemon(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isDaemonRunning() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func registerLaunchd(dbPath, logPath, socketPath string) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.akasha.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>start</string>
    <string>--db</string><string>%s</string>
    <string>--log</string><string>%s</string>
    <string>--socket</string><string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>%s/daemon.log</string>
</dict>
</plist>`, binary, dbPath, logPath, socketPath, filepath.Dir(logPath))

	plistPath := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "dev.akasha.daemon.plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// Load it now.
	launchctl, ok := serviceTool(launchctlPaths)
	if !ok {
		fmt.Println("  ✓ Login service written to " + plistPath)
		fmt.Println("    launchctl not found — load it with: launchctl load " + plistPath)
		return nil
	}
	exec.Command(launchctl, "load", plistPath).Run()
	fmt.Println("  ✓ Daemon registered as login service (launchd)")
	return nil
}

func registerSystemd(dbPath, logPath, socketPath string) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}

	unit := fmt.Sprintf(`[Unit]
Description=Akasha vault daemon
After=network.target

[Service]
ExecStart=%s start --db %s --log %s --socket %s
Restart=always

[Install]
WantedBy=default.target
`, binary, dbPath, logPath, socketPath)

	unitDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return err
	}
	unitPath := filepath.Join(unitDir, "akasha.service")
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return err
	}

	systemctl, ok := serviceTool(systemctlPaths)
	if !ok {
		fmt.Println("  ✓ Login service written to " + unitPath)
		fmt.Println("    systemctl not found — enable it with: systemctl --user enable --now akasha")
		return nil
	}
	exec.Command(systemctl, "--user", "enable", "--now", "akasha").Run()
	fmt.Println("  ✓ Daemon registered as login service (systemd)")
	return nil
}

// The service managers are invoked by absolute path: they start the daemon, so
// a PATH directory any local process can write would otherwise choose what runs
// as the user's login service. Distributions disagree on the location, hence a
// list rather than one constant; nothing here falls back to PATH.
var (
	launchctlPaths = []string{"/bin/launchctl", "/usr/bin/launchctl"}
	systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl", "/sbin/systemctl", "/usr/sbin/systemctl", "/run/current-system/sw/bin/systemctl"}
)

// serviceTool returns the first candidate that exists as an executable file.
func serviceTool(candidates []string) (string, bool) {
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		return p, true
	}
	return "", false
}

// ─── SDK snippets ─────────────────────────────────────────────────────────

func printSDKSnippet(p Provider, key string) {
	fmt.Printf("  ✓ Agent key: %s\n", key)
	fmt.Println("  → Add to your agent:")

	switch p.ID {
	case "ollama":
		fmt.Printf(`
      from akasha.integrations.openai_compat import AkashaOpenAI
      client = AkashaOpenAI(
          agent_id=%q,
          api_key=%q,
          base_url="http://localhost:11434/v1",
          llm_api_key="ollama",
      )
`, p.ID, key)
	case "openai":
		fmt.Printf(`
      from akasha.integrations.openai_compat import AkashaOpenAI
      client = AkashaOpenAI(
          agent_id=%q,
          api_key=%q,
          llm_api_key="sk-...",
      )
`, p.ID, key)
	case "langchain":
		fmt.Printf(`
      from akasha.integrations.langchain import AkashaCallback
      handler = AkashaCallback(agent_id=%q, api_key=%q)
      # Pass to any chain/agent: .invoke(..., config={"callbacks": [handler]})
`, p.ID, key)
	default:
		fmt.Printf(`
      from akasha import Akasha
      vault = Akasha(agent_id=%q, api_key=%q)
`, p.ID, key)
	}
}

// ─── Minimal HTTP helper (no proxy) ───────────────────────────────────────

// noProxyClient bypasses any HTTP_PROXY/HTTPS_PROXY env vars so localhost
// daemon traffic is never routed through an interception proxy.
var noProxyClient = &http.Client{
	Timeout:   2 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

func httpGet(url string) (string, error) {
	resp, err := noProxyClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.String(), nil
}
