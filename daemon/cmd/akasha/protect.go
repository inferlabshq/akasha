package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
)

// daemonVault adapts the daemon socket to the escrow.Vault interface, so
// protect/restore go through the running daemon and get auth, audit, and
// policy for free (a restore is a retrieval — the policy gate applies).
type daemonVault struct{ sock string }

func (d daemonVault) Store(plaintext, category, risk, agentID, tool string, _ time.Duration) (string, error) {
	res, err := daemonPost(d.sock, "/store", map[string]interface{}{
		"agent_id": agentID, "tool_name": tool, "content": plaintext,
		"category": category, "risk": risk,
	})
	if err != nil {
		return "", err
	}
	tok, _ := res["token"].(string)
	if tok == "" {
		return "", fmt.Errorf("daemon did not return a token: %v", res)
	}
	return tok, nil
}

func (d daemonVault) SetLabel(name, token string) error {
	res, err := daemonPost(d.sock, "/label/set", map[string]interface{}{
		"name": name, "token": token,
	})
	if err != nil {
		return err
	}
	if res["status"] != "ok" {
		return fmt.Errorf("label/set failed: %v", res)
	}
	return nil
}

func (d daemonVault) ValueForLabel(name string) (string, error) {
	body, err := daemonGet(d.sock, "/credential/retrieve?name="+url.QueryEscape(name))
	if err != nil {
		return "", err
	}
	var res struct {
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(body), &res) != nil || res.Value == "" {
		return "", fmt.Errorf("%s", strings.TrimSpace(body))
	}
	return res.Value, nil
}

func (d daemonVault) ListLabels(prefix string) ([]string, error) {
	body, err := daemonGet(d.sock, "/label/list?prefix="+url.QueryEscape(prefix))
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal([]byte(body), &names); err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(body))
	}
	return names, nil
}

var (
	protectYes         bool
	protectAllowHardlk bool
)

var protectCmd = &cobra.Command{
	Use:   "protect <file>...",
	Short: "Move a plaintext credential file INTO the vault (reversible)",
	Long: `Escrows the exact bytes and mode of each file into the vault and replaces
it on disk with a comment-only stub. The plaintext then exists ONLY in the
vault: agents (and everything else) can no longer read it from disk, and every
access flows through the daemon — authenticated, audited, policy-gated.

Reversible at any time with 'akasha restore <file>'. 'akasha uninstall'
restores all escrowed files automatically.

Note: your own tools also stop finding the plaintext. For AWS-style
credentials, agent sessions set up by 'akasha setup' keep working through
credential_process; for your own shell, use 'akasha exec --assume
provider:profile -- <cmd>' or wire credential_process into your config.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v := daemonVault{sock: socketPath}

		fmt.Println("This will, for each file:")
		fmt.Println("  1. store its exact bytes + permissions in the vault (encrypted)")
		fmt.Println("  2. replace it on disk with a comment-only stub")
		fmt.Println()
		fmt.Println("Restore any time with `akasha restore <file>`.")
		// "Recommended first: akasha vault backup" alone read as full
		// protection, and it is only the key half — a user who took it that way
		// was one keychain loss away from finding out that the file they saved
		// could not rebuild anything.
		fmt.Println("Recommended first: `akasha vault backup` — that saves the KEY. The bytes")
		fmt.Println("themselves live in ~/.akasha/vault.db; keep a copy of that too.")
		fmt.Println()
		if !protectYes && !confirmEscrow(fmt.Sprintf("Escrow %d file(s)?", len(args))) {
			fmt.Println("Aborted — nothing changed.")
			return nil
		}

		var failed bool
		for _, path := range args {
			token, err := escrow.ProtectWith(v, path, escrow.Options{AllowHardlinked: protectAllowHardlk})
			if err != nil {
				fmt.Printf("  ✗ %s: %v\n", path, err)
				failed = true
				continue
			}
			fmt.Printf("  ✓ %s escrowed (%s) — stub left on disk\n", path, token)
		}
		if failed {
			return fmt.Errorf("some files were not escrowed")
		}
		return nil
	},
}

var (
	restoreAll bool
	restoreYes bool
)

var restoreCmd = &cobra.Command{
	Use:   "restore [<file>...]",
	Short: "Write an escrowed original back to disk, byte-for-byte",
	Long: `Regenerates files escrowed with 'akasha protect' exactly as they were —
same bytes, same permissions. The vault entry is kept, so a file can be
protected again later. Use --all to restore everything escrowed.

This is the reversal of a protection, so it confirms first: pass --yes to skip
the prompt. The daemon separately refuses to hand an escrowed original to an
agent identity, so a restore from inside an agent session fails regardless.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v := daemonVault{sock: socketPath}

		paths := args
		if restoreAll {
			var err error
			paths, err = escrow.List(v)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				fmt.Println("Nothing is escrowed.")
				return nil
			}
		} else if len(paths) == 0 {
			escrowed, err := escrow.List(v)
			if err == nil && len(escrowed) > 0 {
				fmt.Println("Escrowed files (pass a path, or --all):")
				for _, p := range escrowed {
					fmt.Printf("  %s\n", p)
				}
				return nil
			}
			return fmt.Errorf("nothing to restore — pass file paths or --all")
		}

		// Restoring is not the harmless half of the pair. It puts the plaintext
		// back where anything running as this user can read it, undoing the one
		// thing protect promised — and the stub left on disk NAMES this command,
		// so it is the obvious next move for anything that reads the file and
		// can run a shell. An agent's own key cannot get past the daemon here,
		// but the confirmation is what stops a restore that the human never
		// meant to run. Fail closed without a terminal, same as protect.
		fmt.Println("This rewrites the plaintext of:")
		for _, p := range paths {
			fmt.Printf("  %s\n", p)
		}
		fmt.Println()
		fmt.Println("Anything running as you can read those files again afterwards.")
		if !restoreYes && !confirmEscrow(fmt.Sprintf("Restore %d file(s)?", len(paths))) {
			fmt.Println("Aborted — nothing changed.")
			return nil
		}

		var failed bool
		for _, path := range paths {
			if err := escrow.Restore(v, path); err != nil {
				fmt.Printf("  ✗ %s: %v\n", path, err)
				failed = true
				continue
			}
			fmt.Printf("  ✓ %s restored\n", path)
		}
		if failed {
			return fmt.Errorf("some files were not restored")
		}
		return nil
	},
}

// confirmEscrow asks y/N on the terminal; non-interactive sessions must pass
// --yes (fail closed, same convention as uninstall's purge confirmation).
func confirmEscrow(prompt string) bool {
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Println("  (non-interactive session — pass --yes to confirm)")
		return false
	}
	fmt.Printf("%s [y/N]: ", prompt)
	var resp string
	fmt.Scanln(&resp)
	resp = strings.ToLower(strings.TrimSpace(resp))
	return resp == "y" || resp == "yes"
}
