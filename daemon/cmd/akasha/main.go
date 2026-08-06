package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/mcp"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/setup"
	"github.com/inferlabshq/akasha/daemon/internal/template"
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
	discoverYes     bool
	resyncRotate    bool
	uninstallPurge  bool
	uninstallYes    bool
	uninstallExport string
)

func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha")
}

func init() {
	dir := defaultDataDir()
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", filepath.Join(dir, "akasha.sock"), "Unix socket path")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", filepath.Join(dir, "vault.db"), "Vault database path")
	rootCmd.PersistentFlags().StringVar(&logPath, "log", filepath.Join(dir, "audit.log"), "Audit log path")

	startCmd.Flags().BoolVar(&httpOnly, "http-only", false, "Use HTTP listener only (no Unix socket)")
	startCmd.Flags().StringVar(&passphrase, "passphrase", "", "Argon2id passphrase for dual-factor vault protection (optional)")

	agentCmd.AddCommand(agentCreateCmd, agentListCmd, agentRevokeCmd, agentResyncCmd)
	mcpCmd.Flags().StringVar(&mcpAgentID, "agent-id", "claude-code", "Agent identity reported to the vault")
	mcpCmd.Flags().StringVar(&mcpAPIKey, "api-key", "", "Akasha API key (agt_...) for authenticated requests")
	setupCmd.Flags().StringSliceVar(&setupProviders, "providers", nil, "Limit to specific targets: claude,cursor,windsurf,codex,vscode,vscode-insiders (IDEs) or ollama,openai,langchain,custom (SDK). Default: auto-detect installed IDEs.")
	discoverCmd.Flags().BoolVarP(&discoverYes, "yes", "y", false, "Vault all discovered credentials without prompting")
	agentResyncCmd.Flags().BoolVar(&resyncRotate, "rotate", false, "Mint a new key instead of re-admitting the existing one (requires IDE restart)")
	execCmd.Flags().StringArrayVar(&execAssumes, "assume", nil, "Credential to inject as provider:profile (repeatable)")
	execCmd.Flags().IntVar(&execTTL, "ttl", 0, "Credential file lifetime in seconds, a backstop if the process is killed (default 86400 = 24h)")
	putCmd.Flags().BoolVar(&putStdin, "stdin", false, "Read fields as a JSON object {field:value} from stdin")
	vaultCmd.AddCommand(vaultBackupCmd, vaultRestoreCmd, vaultRotateCmd)
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false, "Also delete the vault data and OS-keychain key (destroys agent-stored secrets)")
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "Skip the confirmation prompt before a purge")
	uninstallCmd.Flags().StringVar(&uninstallExport, "export", "", "Write a restorable bundle (vault.db copy + key backup) to this dir before removing anything")
	protectCmd.Flags().BoolVarP(&protectYes, "yes", "y", false, "Skip the confirmation prompt")
	restoreCmd.Flags().BoolVar(&restoreAll, "all", false, "Restore every escrowed file")
	rootCmd.AddCommand(startCmd, logsCmd, inspectCmd, statusCmd, listCmd, assumeCmd, discoverCmd, agentCmd, mcpCmd, setupCmd, vaultCmd, execCmd, putCmd, helperCmd, templateCmd, keygenCmd, publisherCmd, uninstallCmd, policyCmd, protectCmd, restoreCmd)
}

var rootCmd = &cobra.Command{
	Use:   "akasha",
	Short: "Akasha — local vault engine for AI agents",
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Akasha daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd.OutOrStdout())
		// The daemon logs template loads/overrides; CLI commands stay silent.
		template.SetLogf(log.Printf)
		if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
			return err
		}

		// Put assumed credential files on RAM-backed storage so they never
		// touch the SSD (tmpfs on Linux, a RAM disk on macOS). Best-effort.
		ramCleanup := setupSessionStorage()
		defer ramCleanup()

		opts := vault.Options{}
		if passphrase != "" {
			opts.Passphrase = []byte(passphrase)
			fmt.Println("akasha: passphrase protection enabled (Argon2id)")
		}
		vlt, err := vault.Open(dbPath, opts)
		if err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		defer vlt.Close()

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

		fmt.Printf("akasha daemon started (db=%s log=%s)\n", dbPath, logPath)
		wg.Wait()
		return nil
	},
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
			return fmt.Errorf("daemon not reachable: %w", err)
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
			return fmt.Errorf("daemon not reachable: %w", err)
		}
		fmt.Println(resp)
		reportAgentHealth(cmd.OutOrStdout())
		return nil
	},
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
	reportSurplusKeys(w, vlt)
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
  akasha setup --providers claude,ollama  # Claude Code + Ollama SDK snippet`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
'--export' to save a restorable copy first.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return setup.Uninstall(setup.UninstallOptions{
			DataDir:    filepath.Dir(dbPath),
			DBPath:     dbPath,
			LogPath:    logPath,
			SocketPath: socketPath,
			Purge:      uninstallPurge,
			Yes:        uninstallYes,
			ExportDir:  uninstallExport,
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
        "args": ["mcp", "--agent-id", "claude-code", "--api-key", "agt_..."]
      }
    }
  }

The MCP server proxies requests to the running Akasha daemon (akasha start).
Tools exposed: vault_wrap, vault_store, vault_retrieve, vault_grant, vault_inspect, vault_status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return mcp.Run(mcpAgentID, mcpAPIKey)
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
