package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/clikey"
	"github.com/inferlabshq/akasha/daemon/internal/hardening"
	"github.com/inferlabshq/akasha/daemon/internal/mcp"
	"github.com/inferlabshq/akasha/daemon/internal/publisher"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/setup"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
	"github.com/spf13/cobra"
)

var (
	socketPath      string
	dbPath          string
	logPath         string
	httpOnly        bool
	passphrase      string
	mcpAgentID      string
	mcpAPIKey       string
	setupProviders  []string
	setupYes        bool
	discoverYes     bool
	discoverDryRun  bool
	resyncRotate    bool
	uninstallPurge  bool
	uninstallYes    bool
	uninstallExport string
)

func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha")
}

// ensurePrivateDataDir creates the data directory and tightens it to 0700.
//
// MkdirAll applies its mode only when it CREATES a directory, so an install
// whose ~/.akasha was first made under a permissive umask — or by a tool that
// was not akasha — keeps that mode forever and every later MkdirAll silently
// agrees with it. Directory mode is what contains vault.db, its WAL, and the
// socket, so a 0755 data dir publishes all three to every account on the host.
// Re-asserting the mode on each start is the only thing that repairs an install
// that is already wrong.
func ensurePrivateDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("%s is mode %#o, so other accounts on this machine can reach the vault, "+
				"and it could not be tightened — %w\n  Fix it by hand: chmod 700 %s", dir, perm, err, dir)
		}
		log.Printf("akasha: tightened %s from %#o to 0700", dir, perm)
	}
	return nil
}

// requireSubcommand makes a mistyped subcommand an ERROR rather than a help
// screen with a zero exit.
//
// `akasha vault bakcup` printed the vault help and exited 0. A human sees the
// help; a script sees success — and the command it failed to run is the one
// that protects against losing the vault key, so "backup succeeded, wrote
// nothing" is the worst possible shape for that mistake. cobra's default for a
// parent with no Run is exactly that, on every parent command here.
//
// Applied to the parents rather than to each leaf, so a subcommand added later
// inherits it.
func requireSubcommand(c *cobra.Command) *cobra.Command {
	// A parent that already DOES something keeps doing it. `akasha policy` is
	// the one of these six with a real body — it prints the active policy, and
	// there is no `policy show` to fall back on — so overwriting RunE
	// unconditionally did not tighten anything, it deleted the only way to read
	// the policy from the CLI, on a command both README and getting-started
	// tell people to run.
	if c.RunE != nil || c.Run != nil {
		// It keeps its body, but it must still reject a name it does not know:
		// `akasha policy validat` printed the policy and exited 0, so a typo'd
		// subcommand silently did something else that looked like success.
		if c.Args == nil {
			c.Args = func(cmd *cobra.Command, args []string) error {
				if len(args) > 0 {
					return fmt.Errorf("unknown subcommand %q for `%s`.\n\n%s",
						args[0], cmd.CommandPath(), cmd.UsageString())
				}
				return nil
			}
		}
		return c
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unknown subcommand %q for `%s`.\n\n%s",
				args[0], cmd.CommandPath(), cmd.UsageString())
		}
		return fmt.Errorf("`%s` needs a subcommand.\n\n%s", cmd.CommandPath(), cmd.UsageString())
	}
	// No SilenceUsage here: the root's PersistentPreRun already silences it for
	// runtime errors, at the only point where a mistyped FLAG can still be told
	// apart from a mistyped subcommand. Setting it in the struct is what that
	// invariant test forbids, and it forbids it for a good reason.
	return c
}

func init() {
	dir := defaultDataDir()
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(dir, "akasha.sock"), "Unix socket path")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", filepath.Join(dir, "vault.db"), "Vault database path")
	rootCmd.PersistentFlags().StringVar(&logPath, "log", filepath.Join(dir, "audit.log"), "Audit log path")

	startCmd.Flags().BoolVar(&httpOnly, "http-only", false, "Use HTTP listener only (no Unix socket)")
	startCmd.Flags().StringVar(&passphrase, "passphrase", "",
		"Argon2id passphrase for dual-factor vault protection. Pass no value (or -) to be prompted")
	// NoOptDefVal makes the value optional, which is what lets `--passphrase`
	// alone mean "prompt me". The cost is a pflag rule that surprises everyone
	// once: with an optional value, the value must be ATTACHED with `=`.
	// `--passphrase secret` parses as the flag with no value plus a positional
	// argument "secret", so it prompts and then fails on EOF in a script. The
	// Args guard below turns that into a sentence instead.
	startCmd.Flags().Lookup("passphrase").NoOptDefVal = promptSentinel
	startCmd.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		if cmd.Flags().Changed("passphrase") {
			return fmt.Errorf("a passphrase value must be attached with `=`:\n"+
				"  akasha start --passphrase=%s\n"+
				"`--passphrase` on its own means \"prompt me\", which is the safer form —\n"+
				"a value on the command line is readable via /proc by any process running as you.",
				args[0])
		}
		return fmt.Errorf("`akasha start` takes no arguments, got %q", args[0])
	}

	agentCmd.AddCommand(agentCreateCmd, agentListCmd, agentRevokeCmd, agentResyncCmd)
	for _, parent := range []*cobra.Command{agentCmd, vaultCmd, labelCmd, templateCmd, publisherCmd, policyCmd} {
		requireSubcommand(parent)
	}
	mcpCmd.Flags().StringVar(&mcpAgentID, "agent-id", "claude-code", "Agent identity reported to the vault")
	mcpCmd.Flags().StringVar(&mcpAPIKey, "api-key", "", "Akasha API key (agt_...). Deprecated: prefer AKASHA_AGENT_KEY — a key here is visible to every process on the machine via `ps`")
	setupCmd.Flags().BoolVarP(&setupYes, "yes", "y", false, "Answer prompts without asking: trust the shipped provider bundle, VAULT EVERY CREDENTIAL FOUND on this machine, and skip the key backup (which needs a passphrase)")
	setupCmd.Flags().StringSliceVar(&setupProviders, "providers", nil, "Limit to specific targets: claude,cursor,windsurf,codex,vscode,vscode-insiders (IDEs) or ollama,openai,langchain,custom (SDK). Default: auto-detect installed IDEs.")
	discoverCmd.Flags().BoolVarP(&discoverYes, "yes", "y", false, "Vault all discovered credentials without prompting")
	discoverCmd.Flags().BoolVar(&discoverDryRun, "dry-run", false, "Show what would be vaulted and exit without writing anything")
	agentResyncCmd.Flags().BoolVar(&resyncRotate, "rotate", false, "Mint a new key instead of re-admitting the existing one (requires IDE restart)")
	execCmd.Flags().StringArrayVar(&execAssumes, "assume", nil, "Credential to inject as provider:profile (repeatable)")
	execCmd.Flags().IntVar(&execTTL, "ttl", 0, "Credential file lifetime in seconds, a backstop if the process is killed (default 86400 = 24h)")
	runCmd.Flags().StringArrayVar(&runAssumes, "assume", nil, "Credential this run may broker, as provider:instance (repeatable)")
	runCmd.Flags().BoolVar(&runNoSandbox, "no-sandbox", false, "Launch WITHOUT isolation — the agent can read your vault and keychain directly")
	runCmd.Flags().BoolVar(&runPrintProf, "print-profile", false, "Print the sandbox profile that would be applied, and exit")
	runCmd.Flags().IntVar(&runTTL, "ttl", 0, "Seconds the run identity survives if the supervisor is killed (default 28800 = 8h)")
	runCmd.Flags().StringArrayVar(&runAllowRead, "allow-read", nil, "Extra absolute path the sandbox may read (repeatable)")
	runCmd.Flags().StringArrayVar(&runAllowWrite, "allow-write", nil, "Extra absolute path the sandbox may write (repeatable)")
	putCmd.Flags().BoolVar(&putStdin, "stdin", false, "Read fields as a JSON object {field:value} from stdin")
	vaultCmd.AddCommand(vaultBackupCmd, vaultRestoreCmd, vaultRotateCmd)
	policyCmd.AddCommand(policyPassphraseCmd)
	policyPassphraseCmd.Flags().BoolVar(&policyPassphraseClear, "clear", false, "Remove the approval passphrase")
	sandboxCmd.AddCommand(sandboxDoctorCmd)
	sandboxDoctorCmd.Flags().BoolVar(&sandboxDoctorProfile, "profile", false, "Print the full launcher profile as well as the coverage table")
	vaultRestoreCmd.Flags().BoolVar(&vaultRestoreForce, "force", false,
		"Restore even though a DIFFERENT vault key is already on this machine (makes that vault undecryptable)")
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false, "Also delete the vault data and OS-keychain key (destroys agent-stored secrets)")
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "Skip the confirmation prompt before a purge")
	uninstallCmd.Flags().StringVar(&uninstallExport, "export", "", "Write a restorable bundle (vault.db copy + key backup) to this dir before removing anything")
	protectCmd.Flags().BoolVarP(&protectYes, "yes", "y", false, "Skip the confirmation prompt")
	protectCmd.Flags().BoolVar(&protectAllowHardlk, "allow-hardlinked", false, "Escrow a file that has other hardlinks — the plaintext stays readable through them")
	restoreCmd.Flags().BoolVar(&restoreAll, "all", false, "Restore every escrowed file")
	restoreCmd.Flags().BoolVarP(&restoreYes, "yes", "y", false, "Skip the confirmation prompt")
	rootCmd.AddCommand(startCmd, stopCmd, logsCmd, inspectCmd, whoamiCmd, statusCmd, listCmd, labelCmd, assumeCmd, discoverCmd, agentCmd, mcpCmd, setupCmd, vaultCmd, execCmd, putCmd, helperCmd, templateCmd, keygenCmd, publisherCmd, uninstallCmd, policyCmd, protectCmd, restoreCmd,
		runCmd, sandboxSelfTestCmd, requireSubcommand(sandboxCmd), versionCmd)
}

var rootCmd = &cobra.Command{
	Use:     "akasha",
	Short:   "Akasha — local vault engine for AI agents",
	Version: Version(),

	// Cobra prints the flag table after ANY error a command returns, including
	// every error that has nothing to do with syntax. "daemon not reachable",
	// "vault is locked" and the multi-line recovery instructions under it all
	// arrived with a dozen lines of flag help stacked on top, which pushes the
	// message that matters off a short terminal and makes an environment
	// problem read as a CLI mistake. A dozen commands had already turned it off
	// one at a time; the rest — including `start`, where a Linux user meets
	// their first failure — had not.
	//
	// PersistentPreRun is where that is fixable once for every command, present
	// and future. Cobra runs it AFTER flag parsing and argument validation and
	// BEFORE RunE, so the errors where the usage text IS the answer — a
	// mistyped flag, a wrong argument count — still print it, and only errors
	// raised by a command's own body are silenced. Setting it here rather than
	// on each command also means a new subcommand inherits the behaviour
	// instead of having to remember it.
	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		cmd.SilenceUsage = true
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Akasha daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		// The reason a start fails is almost always the vault refusing to open,
		// and those errors are multi-line recovery instructions. Cobra's flag
		// table printed underneath pushes them off a short terminal. Silenced
		// from inside RunE rather than on the command, because flag parsing
		// happens first and a mistyped flag is exactly the error where the
		// usage text is the answer.
		cmd.SilenceUsage = true
		printBanner(cmd.OutOrStdout())
		// The daemon logs template loads/overrides; CLI commands stay silent.
		template.SetLogf(log.Printf)
		if err := ensurePrivateDataDir(filepath.Dir(dbPath)); err != nil {
			return err
		}

		// Put assumed credential files on RAM-backed storage so they never
		// touch the SSD (tmpfs on Linux, a RAM disk on macOS). Best-effort.
		ramCleanup := setupSessionStorage()
		defer ramCleanup()

		// Say so when this is a NEW vault.
		//
		// The rekey guard used to catch a mistyped --db as a side effect: the
		// machine's single keychain entry was already taken, so a second vault
		// was refused. Per-vault keys removed that collision — and with it the
		// accident's only symptom, since a typo now just creates an empty vault
		// and reports nothing. This says it plainly instead of relying on a
		// guard that fires for a different reason.
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			fmt.Printf("akasha: creating a NEW vault at %s\n", dbPath)
			fmt.Println("        (if you did not mean to, check --db — an existing vault is elsewhere)")
		}

		// Before the key is loaded, not after: a limit raised once the secret is
		// already in memory has missed the window a crash could have used.
		if h := hardening.Apply(); len(h.Applied) > 0 || len(h.Skipped) > 0 {
			fmt.Printf("akasha: process hardening — %s\n", h.Summary())
		}

		opts := vault.Options{}
		if pass, err := resolveVaultPassphrase(cmd); err != nil {
			return err
		} else if len(pass) > 0 {
			opts.Passphrase = pass
			fmt.Println("akasha: passphrase protection enabled (Argon2id) —")
			fmt.Println("        the OS keychain alone can no longer open this vault.")
		}
		vlt, err := vault.Open(dbPath, opts)
		if err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		defer vlt.Close()

		// Give the local CLI an identity before anything is served.
		//
		// The daemon refuses unauthenticated callers, so without this the human
		// would have no way to talk to their own daemon. Provisioning happens
		// here rather than in `akasha setup` because minting needs the vault —
		// which is the daemon's to open — and because the CLI must work on a
		// fresh install where setup has never run.
		if _, err := clikey.Ensure(vlt, clikey.Path(dbPath)); err != nil {
			return fmt.Errorf("provision cli key: %w", err)
		}

		auditL, err := audit.New(logPath)
		if err != nil {
			return err
		}
		defer auditL.Close()

		// Load custom patterns from ~/.akasha/patterns.yaml if present.
		patternsPath := filepath.Join(filepath.Dir(dbPath), "patterns.yaml")
		extra, perr := classifier.LoadConfig(patternsPath)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "akasha: ignoring custom patterns (%v)\n", perr)
		} else if len(extra) > 0 {
			fmt.Printf("akasha: loaded %d custom pattern(s) from %s\n", len(extra), patternsPath)
		}
		clf := classifier.New(extra)
		srv := server.New(clf, vlt, auditL)

		// Background TTL enforcement — purge expired vault tokens hourly.
		go func() {
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				if n, err := vlt.PurgeExpired(); err == nil && n > 0 {
					fmt.Fprintf(os.Stderr, "akasha: purged %d expired entries\n", n)
				}
			}
		}()

		// Sweep expired assumed-credential files every minute, so a credential
		// file self-destructs near its TTL even if no further assume happens.
		// (Each file's expiry is encoded as its mtime.)
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				if n := assume.SweepExpired(); n > 0 {
					fmt.Fprintf(os.Stderr, "akasha: swept %d expired credential file(s)\n", n)
				}
			}
		}()

		var wg sync.WaitGroup
		if !httpOnly {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := srv.ListenUnix(socketPath); err != nil {
					fmt.Fprintln(os.Stderr, "unix socket error:", err)
				}
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.ListenHTTP(); err != nil {
				fmt.Fprintln(os.Stderr, "http error:", err)
			}
		}()

		// /shutdown enters the same path a SIGTERM does, so a stop requested
		// over the socket drains and checkpoints exactly like a signalled one.
		// Non-blocking: the channel is buffered, and a second stop request
		// while one is already in flight is a no-op, not a block.
		sigc := shutdownSignals()
		srv.SetStopper(func() {
			select {
			case sigc <- syscall.SIGTERM:
			default:
			}
		})

		fmt.Printf("akasha daemon started (db=%s log=%s)\n", dbPath, logPath)
		serveUntilShutdown(&wg, sigc, srv.Shutdown, shutdownGrace)
		return nil
	},
}

// shutdownSignals returns the channel a clean stop arrives on.
//
// The daemon used to register nothing, so launchd/systemd/^C killed it outright
// and not one deferred Close ran. The defer that matters is the vault's:
// SQLite in WAL mode leaves every write in vault.db-wal until something
// checkpoints, and it only checkpoints itself once the log passes ~1000 pages,
// which a personal vault never reaches. Data at rest was never at risk — the
// WAL is part of the database — but vault.db ALONE stayed a 4 KB header, and
// vault.db alone is what a human copies to back up, to move machines, or out of
// `uninstall --export`. Every one of those took away an empty vault.
//
// SIGHUP is in the set because a daemon started from a terminal is sent one on
// hangup and would otherwise die the same silent way; akasha has no config to
// reload, so treating it as "stop cleanly" loses nothing.
func shutdownSignals() chan os.Signal {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return sigc
}

// shutdownGrace bounds each half of a clean stop — draining in-flight requests,
// then waiting for the listeners to come back. Both halves have to fit inside
// the window an init system allows between its stop signal and SIGKILL, which
// is 20 seconds under launchd.
const shutdownGrace = 5 * time.Second

// serveUntilShutdown blocks until the listeners stop on their own or a
// termination signal arrives, then drains in-flight requests and returns so the
// caller's defers can run.
//
// Split out of startCmd because the bug it prevents is only observable as a
// process that never leaves this wait, which is untestable inline. Every wait
// here is bounded: nothing may hold the vault open indefinitely, since closing
// it — and checkpointing its write-ahead log — is the entire point of getting
// here.
func serveUntilShutdown(wg *sync.WaitGroup, sigc <-chan os.Signal, shutdown func(context.Context), grace time.Duration) {
	listenersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(listenersDone)
	}()

	select {
	case s := <-sigc:
		fmt.Fprintf(os.Stderr, "akasha: %v — shutting down\n", s)
	case <-listenersDone:
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	shutdown(ctx)

	// The wait for the listeners is bounded too, and that bound is the whole
	// safeguard: a listener that outlives shutdown parks the process here with
	// the termination signals already trapped, so the daemon goes on serving
	// credentials, every further SIGTERM is swallowed, and only SIGKILL ends
	// it. Giving up and returning is strictly better — the vault still gets
	// closed on the way out.
	select {
	case <-listenersDone:
	case <-time.After(grace):
		fmt.Fprintln(os.Stderr, "akasha: a listener did not stop within the grace period — exiting anyway")
	}
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Tail the local audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(logPath)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(
			&bytesReader{b: data},
		)
		for dec.More() {
			var e map[string]interface{}
			if err := dec.Decode(&e); err != nil {
				break
			}
			line, _ := json.MarshalIndent(e, "", "  ")
			fmt.Println(string(line))
		}
		return nil
	},
}

var inspectCmd = &cobra.Command{
	Use:   "inspect <token>",
	Short: "Show metadata for a vault token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token := args[0]
		resp, err := daemonGet(socketPath, fmt.Sprintf("/inspect?token=%s", token))
		if err != nil {
			return err
		}
		fmt.Println(resp)
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list [provider]",
	Short: "List assumable credentials (provider:profile), optionally for one provider",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		prefix := ""
		if len(args) == 1 {
			prefix = args[0] + ":"
		}
		resp, err := daemonGet(socketPath, "/label/list?prefix="+prefix)
		if err != nil {
			// Unwrapped, for the reason spelled out at the same call in put.go:
			// daemonGet already says so when the daemon really is unreachable,
			// and pasting that guess over a considered REFUSAL made a policy
			// denial read as a connection problem.
			return err
		}
		var names []string
		if err := json.Unmarshal([]byte(resp), &names); err != nil {
			return fmt.Errorf("unexpected response: %s", resp)
		}
		if len(names) == 0 {
			fmt.Println("Nothing vaulted yet — run `akasha discover all` or `akasha put <provider>:<name>`.")
			return nil
		}
		// Group by provider so the output reads as assume targets.
		byProvider := map[string][]string{}
		var providers []string
		for _, n := range names {
			i := strings.Index(n, ":")
			if i <= 0 {
				continue
			}
			p := n[:i]
			if _, seen := byProvider[p]; !seen {
				providers = append(providers, p)
			}
			byProvider[p] = append(byProvider[p], n[i+1:])
		}
		sort.Strings(providers)
		for _, p := range providers {
			fmt.Printf("%s:\n", p)
			for _, inst := range byProvider[p] {
				fmt.Printf("  %s:%s\n", p, inst)
			}
		}
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Health check and vault statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := daemonGet(socketPath, "/health")
		if err != nil {
			return err // already self-describing; see the note in put.go
		}
		fmt.Println(resp)
		reportBrokenSubsystems(cmd.OutOrStdout(), resp)
		reportAgentHealth(cmd.OutOrStdout())
		reportTemplateTrust(cmd.OutOrStdout())
		return nil
	},
}

// reportBrokenSubsystems turns the health JSON into the sentence a reader
// needed, for the two states that make the daemon useless while it reports ok.
//
// `status` is documented as the health check and answered {"status":"ok"} with
// zero templates loaded — so nothing could be brokered — and with a policy the
// daemon had failed to parse, which denies everything. Both are states where
// every later command fails for a reason `status` already knew and did not say,
// and both sent readers to blame the credential instead. Six of seven reviewers
// of this daemon were misled by that answer at least once.
//
// Printed after the JSON rather than replacing it: the raw object is what
// scripts read, and quietly changing its shape would break them.
func reportBrokenSubsystems(w io.Writer, health string) {
	var h struct {
		TemplatesLoaded *int   `json:"templates_loaded"`
		Policy          string `json:"policy"`
	}
	if err := json.Unmarshal([]byte(health), &h); err != nil {
		return
	}
	if h.TemplatesLoaded != nil && *h.TemplatesLoaded == 0 {
		fmt.Fprintln(w, "  ⚠ NO PROVIDER TEMPLATES ARE LOADED — nothing can be brokered.")
		fmt.Fprintln(w, "    Every `assume`/`exec` will fail, and the error will name the provider")
		fmt.Fprintln(w, "    rather than this. Check `akasha template list`.")
	}
	if strings.HasPrefix(h.Policy, "invalid") {
		fmt.Fprintln(w, "  ⚠ THE POLICY FILE DOES NOT PARSE, so the daemon is denying operations it")
		fmt.Fprintln(w, "    would otherwise allow:")
		fmt.Fprintf(w, "      %s\n", strings.TrimPrefix(h.Policy, "invalid: "))
		fmt.Fprintln(w, "    Fix it, or move it aside; `akasha policy validate` shows the detail.")
	}
}

// reportTemplateTrust warns when providers are trusted by a local, hash-bound
// approval rather than by a publisher signature.
//
// The two look identical day to day and behave completely differently across an
// upgrade. trust.Approved checks a publisher signature FIRST, so a signed
// provider stays trusted no matter how often its file changes. Without a
// signature it falls back to a record bound to the file's SHA-256 — so the next
// release that edits that template silently revokes the approval, and the user
// finds out at use time, mid-workflow, with "template not trusted yet".
//
// Saying so here turns a recurring mystery into a known, one-line state. It is
// best-effort: a trust store that will not load is not worth failing status over.
func reportTemplateTrust(w io.Writer) {
	providers := template.Providers()
	if len(providers) == 0 {
		return
	}
	store, err := trust.Load()
	if err != nil {
		return
	}
	var hashBound, untrusted []string
	for _, tpl := range providers {
		if len(tpl.SensitiveCapabilities()) == 0 {
			continue // inert: nothing to approve
		}
		if _, signed, err := publisher.VerifyTemplate(tpl.Origin()); err == nil && signed {
			continue // signature-trusted: survives upgrades
		}
		if ok, _ := store.Approved(tpl); ok {
			hashBound = append(hashBound, tpl.Name)
		} else {
			untrusted = append(untrusted, tpl.Name)
		}
	}
	if len(hashBound) == 0 && len(untrusted) == 0 {
		return
	}
	fmt.Fprintln(w, "\nProvider trust:")
	// Lead with the cause when there is one. Without a compiled-in trust root,
	// no bundle can ever be signature-trusted on this build, so listing
	// hash-bound providers without saying why reads as something the user did
	// wrong rather than a property of the binary they installed.
	if !publisher.OfficialConfigured() {
		fmt.Fprintln(w, "  This build has NO official trust root, so signature trust is unavailable and")
		fmt.Fprintln(w, "  every provider below falls back to a hash-bound approval. (`akasha version`)")
	}
	if len(hashBound) > 0 {
		sort.Strings(hashBound)
		fmt.Fprintf(w, "  %d approved by file hash, not by signature: %s\n", len(hashBound), strings.Join(hashBound, ", "))
		fmt.Fprintln(w, "    These will need re-approving after any release that edits them.")
		fmt.Fprintln(w, "    A signed bundle would not: `akasha publisher list` shows who you trust.")
	}
	if len(untrusted) > 0 {
		sort.Strings(untrusted)
		fmt.Fprintf(w, "  %d not trusted yet: %s\n", len(untrusted), strings.Join(untrusted, ", "))
		fmt.Fprintln(w, "    Review with `akasha template explain <name>`, approve with `akasha template trust <name>`.")
	}
}

// reportAgentHealth surfaces MCP clients whose configured key is out of sync
// with the vault — the cause of the cryptic "invalid or revoked agent key" 401
// that otherwise only shows up at tool-call time. It is best-effort: if the
// vault can't be opened (e.g. keychain locked) the check is silently skipped so
// it never turns a healthy `status` into a failure.
func reportAgentHealth(w io.Writer) {
	vlt, err := vault.Open(dbPath, vault.Options{})
	if err != nil {
		return
	}
	defer vlt.Close()

	var desynced, revoked []setup.AgentHealth
	for _, h := range setup.CheckAgents(vlt) {
		switch {
		case h.Resyncable():
			desynced = append(desynced, h)
		case h.State == setup.HealthRevoked:
			revoked = append(revoked, h)
		}
	}
	if len(desynced) == 0 && len(revoked) == 0 {
		// Nothing is broken in the CONFIGS — but the key this session is
		// actually presenting may still be stale, and that state is invisible
		// here unless we look at it.
		reportSessionKey(w, vlt, true)
		// Nothing is broken, but surplus keys are still worth reporting — they
		// are the healthy-looking case, which is exactly why nobody notices.
		reportSurplusKeys(w, vlt)
		return
	}

	fmt.Fprintln(w, "\nAgent keys:")
	for _, h := range desynced {
		fmt.Fprintf(w, "  ⚠ %s (%s): configured key not in the vault — MCP tools will fail.\n", h.Client, h.AgentID)
		fmt.Fprintf(w, "    Fix: akasha agent resync %s   (re-authorizes the existing key, no restart)\n", h.ID)
	}
	for _, h := range revoked {
		fmt.Fprintf(w, "  ⚠ %s (%s): configured key was revoked. If intentional, leave it;\n", h.Client, h.AgentID)
		fmt.Fprintf(w, "    otherwise issue a new one: akasha agent resync %s --rotate (then restart %s)\n", h.ID, h.Client)
	}
	reportSessionKey(w, vlt, false)
	reportSurplusKeys(w, vlt)
}

// reportSessionKey checks the key THIS PROCESS is carrying in its environment,
// which is a different thing from the keys in the client configs.
//
// The gap this closes: setup injects AKASHA_AGENT_KEY into an agent harness
// session, and a session that is already running keeps the environment it
// started with. Rotate the keys and every config is immediately correct while
// the live session still presents the old one. `akasha status` reported
// "healthy" — it only ever compared CONFIGS to the vault — and every other
// command failed with "agent key has been revoked", whose advice is to rotate.
// Rotating rewrites configs that were never broken and forces IDE restarts, so
// the one diagnostic a user runs sent them toward the wrong repair.
//
// configsHealthy decides the remedy, which is the whole point of reporting it
// separately: a stale session key with sound configs needs a new session, not
// new keys.
func reportSessionKey(w io.Writer, vlt *vault.Vault, configsHealthy bool) {
	key := os.Getenv("AKASHA_AGENT_KEY")
	if key == "" {
		// No agent key in this environment means this is a plain shell, which
		// authenticates with the CLI's own key instead — nothing to report.
		return
	}
	if _, err := vlt.VerifyAgentKey(key); err == nil {
		return // healthy — status stays quiet when there is nothing to say
	} else if !errors.Is(err, vault.ErrAgentKeyRevoked) && !errors.Is(err, vault.ErrAgentKeyInvalid) {
		return // best-effort: an unreadable vault must not fail status
	} else {
		fmt.Fprintln(w, "\nThis session's agent key:")
		if errors.Is(err, vault.ErrAgentKeyRevoked) {
			fmt.Fprintln(w, "  ⚠ AKASHA_AGENT_KEY in this environment was REVOKED.")
		} else {
			fmt.Fprintln(w, "  ⚠ AKASHA_AGENT_KEY in this environment is not recognised by the vault.")
		}
	}

	if configsHealthy {
		fmt.Fprintln(w, "    Your client configs are fine — only this already-running session is stale,")
		fmt.Fprintln(w, "    because it kept the environment it started with when the key was rotated.")
		fmt.Fprintln(w, "    Fix: start a new session, which will pick up the current key.")
		// This deliberately no longer suggests `unset AKASHA_AGENT_KEY`. That
		// used to "work" because a keyless caller was taken for the human and
		// handed MORE access than the key carried — so the diagnostic was
		// printing the revocation bypass as its remedy. Unsetting now leaves the
		// session with no identity at all, and the daemon refuses it.
		fmt.Fprintln(w, "    Do NOT run `agent resync --rotate` — it would rewrite working configs")
		fmt.Fprintln(w, "    and force an IDE restart to fix something that is not broken.")
		return
	}
	fmt.Fprintln(w, "    A configured client is out of sync too — repair that first (above), then")
	fmt.Fprintln(w, "    start a new session so this one stops presenting the old key.")
}

// reportSurplusKeys flags agents holding more than one active key.
//
// Until this release every `akasha setup` run minted a key and left the
// previous one valid, so a machine set up a few times carries several working
// credentials per agent — each a complete impersonation of it, none in use, and
// nothing anywhere saying so. New rotations retire the key they replace, but
// keys that accumulated before that are still live and only the user can decide
// which to keep.
func reportSurplusKeys(w io.Writer, vlt *vault.Vault) {
	keys, err := vlt.ListAgentKeys()
	if err != nil {
		return
	}
	active := map[string][]string{}
	for _, k := range keys {
		if !k.Revoked {
			active[k.AgentID] = append(active[k.AgentID], k.KeyID)
		}
	}
	var surplus []string
	for agent, ids := range active {
		if len(ids) > 1 {
			surplus = append(surplus, fmt.Sprintf("%s (%d keys)", agent, len(ids)))
		}
	}
	if len(surplus) == 0 {
		return
	}
	sort.Strings(surplus)
	fmt.Fprintf(w, "  ⚠ more than one active key: %s\n", strings.Join(surplus, ", "))
	fmt.Fprintln(w, "    Each is a full credential for that agent. Older ones are left over from")
	fmt.Fprintln(w, "    earlier setup runs and are almost certainly unused:")
	fmt.Fprintln(w, "      akasha agent list              # newest first")
	fmt.Fprintln(w, "      akasha agent revoke <key-id>   # retire the ones you don't recognise")
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "First-run setup — configure agents and start the daemon",
	Long: `First-run setup. Starts the daemon as a login service, discovers and
vaults credentials, backs up the key, then auto-detects installed MCP IDEs
(Claude Code, Cursor, Windsurf, Codex, VS Code Copilot) and writes each one's
config — every IDE gets its own agent identity in the audit log.

  akasha setup                            # auto-detect & configure installed IDEs
  akasha setup --providers vscode         # just VS Code (Copilot agent mode)
  akasha setup --providers claude,ollama  # Claude Code + Ollama SDK snippet
  akasha setup --yes                      # unattended (devcontainer, CI, script)

--yes answers the prompts without asking. Be clear about what it consents to on
your behalf: it VAULTS EVERY CREDENTIAL DISCOVERY FINDS on this machine, with no
review step. That is the point of an unattended install, and it is not something
to reach for casually — run "akasha discover all --dry-run" first to see exactly
what would be taken.

It trusts the SHIPPED provider bundle but never a template you dropped in
~/.akasha/templates/, and it cannot create the key backup, which needs a
passphrase. It says so loudly — that backup is what recovers your vault if the
OS keychain entry is lost.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		setup.AssumeYes = setupYes
		return setup.Run(dbPath, logPath, socketPath, setupProviders)
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop & deregister the daemon; optionally purge the vault",
	Long: `Reverses 'akasha setup'. By default it stops and deregisters the daemon
but leaves all vault data and the keychain key intact, so nothing is lost.

  akasha uninstall                       # stop daemon, keep vault data
  akasha uninstall --export ~/akasha-out # save a restorable bundle first
  akasha uninstall --purge               # also delete vault + keychain key
  akasha uninstall --purge --export ~/akasha-out

Agent-wrapped secrets live only in the vault — '--purge' destroys them. Use
'--export' to save a restorable copy first.

--purge deletes the directory CONTAINING --db, so it refuses unless that
directory really is akasha's: the vault must have existed when the command
started, and be a vault or sit among akasha's own files. It never removes a
home directory or a top-level one.

The machine's keychain key is removed only if this vault opened with it. That
entry is one per install, not one per vault, so a vault akasha could not open is
no basis for deleting a key another vault may still need.

The akasha BINARY is never deleted — nothing here removes the program you are
running. Delete it yourself afterwards.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Uninstall's failures are recovery instructions, several lines long,
		// and cobra's flag table after a RunE error buries them. Silenced here
		// and not on the command so a mistyped flag still gets its usage.
		cmd.SilenceUsage = true
		return setup.Uninstall(setup.UninstallOptions{
			DataDir:    filepath.Dir(dbPath),
			DBPath:     dbPath,
			LogPath:    logPath,
			SocketPath: socketPath,
			Purge:      uninstallPurge,
			Yes:        uninstallYes,
			ExportDir:  uninstallExport,

			// The authenticated stop, and the liveness test that decides
			// whether this uninstall may call itself complete. Both live here
			// because the caller key does.
			StopDaemon: func() error {
				_, err := daemonPost(socketPath, "/shutdown", map[string]interface{}{})
				if err != nil {
					return err
				}
				if !WaitUntilStopped(socketPath, stopWait) {
					return fmt.Errorf("still answering %s after %s", socketPath, stopWait)
				}
				return nil
			},
			DaemonAlive: func() bool { return DaemonReachable(socketPath) },
		})
	},
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Launch the Akasha MCP server over stdio",
	Long: `Starts a Model Context Protocol server on stdin/stdout.

Claude Code / Codex / Cursor config:

  {
    "mcpServers": {
      "akasha": {
        "command": "akasha",
        "args": ["mcp", "--agent-id", "claude-code"],
        "env": { "AKASHA_AGENT_KEY": "agt_..." }
      }
    }
  }

The key belongs in "env", not in "args": a command line is readable by every
process on the machine, so a key in args can be lifted with ps and used to act
under this agent's identity. --api-key still works, for configs written before
that changed; running "akasha setup" again rewrites them.

The MCP server proxies requests to the running Akasha daemon (akasha start).
Tools exposed: vault_wrap, vault_store, vault_retrieve, vault_grant, vault_inspect, vault_status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return mcp.Run(mcpAgentID, mcpKey(mcpAPIKey))
	},
}

// mcpKey resolves the agent key this MCP server presents to the daemon.
//
// The environment is the form `akasha setup` writes, because a key on the
// command line is readable by every process on the machine. The flag still
// wins when it is present: a config written before the change names its key
// there explicitly, and an explicit value must not be silently overridden by
// whatever ambient AKASHA_AGENT_KEY the surrounding session happens to carry.
func mcpKey(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("AKASHA_AGENT_KEY")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// promptSentinel is what cobra stores when `--passphrase` is given with no
// value. It is "-" — the conventional read-from-stdin marker — rather than a
// control byte, because cobra renders NoOptDefVal into the help text and an
// unprintable one comes out as `--passphrase string[="  prompt"]`.
//
// A sentinel at all, rather than "", because "" also means "flag absent" and
// those two must not collapse into one case.
const promptSentinel = "-"

// resolveVaultPassphrase decides where the vault passphrase comes from.
//
// A passphrase given ON THE COMMAND LINE lands in /proc/<pid>/cmdline, which
// any process running as the same user can read — and that is the exact
// adversary a vault passphrase exists to stop, since the OS keychain hands its
// half to any same-uid caller on both platforms. Delivering the one secret that
// is stored nowhere through the most readable channel on the machine defeats
// the point of having it.
//
// The value form is kept, because a systemd unit or a CI runner has no
// terminal to prompt on, but it says what it costs.
func resolveVaultPassphrase(cmd *cobra.Command) ([]byte, error) {
	if !cmd.Flags().Changed("passphrase") {
		return nil, nil
	}
	if passphrase != promptSentinel {
		fmt.Fprintln(os.Stderr,
			"akasha: WARNING — a passphrase given on the command line is readable via\n"+
				"  /proc by any process running as you, which is the adversary it exists to\n"+
				"  stop. Omit the value to be prompted instead.")
		return []byte(passphrase), nil
	}
	fmt.Print("Vault passphrase: ")
	pass, err := readPassphrase()
	if err != nil {
		// The common case is a script: `--passphrase` prompts, and there is no
		// terminal and nothing piped. Naming both ways out beats reporting EOF.
		return nil, fmt.Errorf("no passphrase was given (%v).\n"+
			"  Pipe it:            echo -n '<pass>' | akasha start --passphrase\n"+
			"  Or pass it inline:  akasha start --passphrase=<pass>   (readable via /proc)", err)
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("empty passphrase; nothing was opened")
	}
	return pass, nil
}
