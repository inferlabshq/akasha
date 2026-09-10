package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
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

// DeleteLabel drops a label through the daemon.
//
// The daemon is the right place for this even though restore already holds the
// bytes: /label/delete refuses to unbind an escrow label whose original is not
// actually back on disk (escrowOnlyCopy + RestoredOnDisk, server.go), so the
// check that the restore really landed is made against the file rather than
// against restore's own belief that it wrote one.
func (d daemonVault) DeleteLabel(name string) error {
	res, err := daemonPost(d.sock, "/label/delete", map[string]interface{}{"name": name})
	if err != nil {
		return err
	}
	if res["status"] != "ok" {
		return fmt.Errorf("label/delete failed: %v", res)
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
credential_process; for your own shell, use 'akasha exec --with
provider:profile -- <cmd>' or wire credential_process into your config.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Protect is human-only, and the reason is specific: an escrow label is
		// the only handle on a file taken off disk, and `akasha restore` writes
		// escrowed bytes BACK to the path the label names. An agent that could
		// create escrow labels could therefore write any file it liked, as you,
		// the next time a restore ran.
		//
		// So this refuses inside an agent session — but it refuses HERE, before
		// the daemon is called, because the daemon's answer is a 403 phrased for
		// a broker ("use the credential through its broker instead"), which is
		// the opposite of what protect does and is exactly the advice a model
		// will relay to its user. What that user needs is the command to run.
		//
		// This is a handoff, not a wall: the person is right there, and the one
		// thing they cannot do is prove it through a key their agent also holds.
		// The check is deliberately on the ENVIRONMENT rather than on the key,
		// because that is what says "an agent is driving this shell".
		if id := os.Getenv("AKASHA_AGENT_ID"); id != "" || os.Getenv("AKASHA_AGENT_KEY") != "" {
			return fmt.Errorf("`akasha protect` removes the plaintext copy of a credential, so it is done by "+
				"the person at the keyboard — not from inside an agent session (this one is %s).\n\n"+
				"  Run this in your own terminal:\n      akasha protect %s\n\n"+
				"  Nothing has been changed. The file is still on disk exactly as it was.",
				agentSessionName(id), strings.Join(args, " "))
		}

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
	restoreAll     bool
	restoreYes     bool
	restoreOffline bool
)

var restoreCmd = &cobra.Command{
	Use:   "restore [<file>...]",
	Short: "Write an escrowed original back to disk, byte-for-byte",
	Long: `Regenerates files escrowed with 'akasha protect' exactly as they were —
same bytes, same permissions. The vault entry is kept, so a file can be
protected again later. Use --all to restore everything escrowed.

This is the reversal of a protection, so it confirms first: pass --yes to skip
the prompt, and it refuses to run from inside an agent session at all.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Same refusal protect carries, and for the same reason: putting an
		// escrowed plaintext back on disk is the reversal of a protection, so
		// it is done by the person at the keyboard.
		//
		// The Long text above used to lean on the daemon for this — "the daemon
		// separately refuses ... so a restore from inside an agent session
		// fails regardless". True of THIS path, and it was never the whole
		// story: `akasha uninstall` reaches the same envelopes through
		// escrow.Direct, which never touches the daemon. Both doors now carry
		// the check, so neither depends on the other being shut.
		if id := os.Getenv("AKASHA_AGENT_ID"); id != "" || os.Getenv("AKASHA_AGENT_KEY") != "" {
			return fmt.Errorf("`akasha restore` puts the plaintext of a protected file back on disk, so it is "+
				"done by the person at the keyboard — not from inside an agent session (this one is %s).\n\n"+
				"  Run this in your own terminal:\n      akasha restore %s\n\n"+
				"  Nothing has been changed. The file on disk is still the stub.",
				agentSessionName(id), strings.Join(args, " "))
		}

		// OFFLINE: open the vault directly instead of going through the daemon.
		//
		// The stub this command is named in promises the file can be recovered.
		// Without this, "the daemon will not start" also means "I cannot get my
		// own file back by hand", which makes that promise false exactly when it
		// matters.
		//
		// This is NOT new capability. Until the previous commit, `akasha
		// uninstall` reached the same envelopes through escrow.Direct with no
		// prompt, no agent check and no audit record — the door was already
		// open and merely misnamed. That door is shut now; this reopens a
		// narrower, audited, human-only version of it deliberately.
		//
		// It also does not create a route past the daemon's escrow gate,
		// because that gate was never a wall against the local human:
		// `server.go:469` says a process that steals cli.key is the human as far
		// as it can tell, so `env -u AKASHA_AGENT_ID akasha restore --yes`
		// already reaches the same bytes THROUGH the daemon. What --offline
		// genuinely removes is the audit record, which is why the append below
		// is not optional.
		//
		// ── THE CONDITION THAT RETIRES THIS FLAG ────────────────────────────
		// If akasha ever gains a real same-UID boundary — peer code-signature
		// attestation, an enclave-bound key, anything that makes a same-uid
		// process stop being indistinguishable from the human — then the daemon
		// BECOMES the wall, and this flag becomes the hole that walks around it.
		// At that moment it must be re-gated or removed. Written here rather
		// than in a design note because this is where someone will meet it.
		var v restoreVault = daemonVault{sock: socketPath}
		if restoreOffline {
			vlt, err := vault.Open(dbPath, vault.Options{Passphrase: nil})
			if err != nil {
				return fmt.Errorf("--offline could not open the vault directly: %w", err)
			}
			defer vlt.Close()
			v = directVault{escrow.Direct{Vault: vlt}}
		}

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
		// --yes is honoured on the daemon path and deliberately NOT offline.
		//
		// Offline drops the daemon's gate and the identity check that goes with
		// it, so the terminal is the only remaining evidence a human is here. A
		// flag that skips it would let a script hold every property this path
		// was allowed to keep and none of the ones it was allowed to drop.
		skipPrompt := restoreYes && !restoreOffline
		if !skipPrompt && !confirmEscrow(fmt.Sprintf("Restore %d file(s)?", len(paths))) {
			if restoreOffline && restoreYes {
				fmt.Println("  --yes does not apply to --offline: this path has no daemon gate,")
				fmt.Println("  so the terminal is the only thing left saying a human is here.")
			}
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
			// The vault's copy goes with it.
			//
			// escrow.Restore used to leave the entry — "re-protect overwrites
			// it" — so every protect/restore round left a permanent escrow
			// label over a file sitting untouched on disk. Two costs. An
			// encrypted duplicate of a file the user just put back is a stale
			// secret copy, not a feature. And any later check that reads "does
			// this vault hold escrowed originals" sees a name with nothing
			// behind it, so a purge gate keyed on that walls a user who only
			// ever tried protect once and changed their mind.
			//
			// The daemon decides, not this loop: /label/delete refuses unless
			// the original is genuinely on disk, so a restore that reported
			// success without landing keeps its label and says so.
			label, lerr := escrow.Label(path)
			if lerr == nil {
				lerr = v.DeleteLabel(label)
			}
			if lerr != nil {
				fmt.Printf("  ✓ %s restored — but the vault still holds a copy: %v\n", path, lerr)
				continue
			}
			auditOfflineRestore(path)
			fmt.Printf("  ✓ %s restored — the vault no longer holds a copy\n", path)
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

// restoreVault is what restore needs: the escrow operations, plus the ability to
// drop a label once the original is genuinely back on disk.
type restoreVault interface {
	escrow.Vault
	DeleteLabel(name string) error
}

// directVault adapts escrow.Direct to that interface for the offline path.
//
// The daemon refuses to unbind an escrow label whose original is not actually on
// disk (escrowOnlyCopy + RestoredOnDisk). Offline there is no daemon to ask, so
// the check is made here instead — against the FILE, not against Restore's own
// belief that it wrote one. Trusting the return value would delete the only copy
// on exactly the runs that went wrong.
type directVault struct{ escrow.Direct }

func (d directVault) DeleteLabel(name string) error {
	blob, err := d.ValueForLabel(name)
	if err != nil {
		return err
	}
	path := strings.TrimPrefix(name, escrow.LabelPrefix)
	if !escrow.RestoredOnDisk(blob, path) {
		return fmt.Errorf("what is on disk is not the escrowed original")
	}
	_, err = d.Vault.DeleteLabel(name)
	return err
}

// auditOfflineRestore records a plaintext leaving the vault on the path that
// bypasses the daemon.
//
// Not optional, and not silent on failure. The daemon writes an audit record for
// every retrieval, and --offline exists precisely by NOT going through it — so
// without this the one honest cost of the flag would be unrecorded, and
// protect.go's claim that "every access flows through the daemon —
// authenticated, audited, policy-gated" would be false in a second place.
//
// If the log cannot be written it says so and the restore proceeds anyway.
// Refusing someone their own file to protect a log is the wrong trade; hiding
// that the log was not written is a worse one.
func auditOfflineRestore(path string) {
	if !restoreOffline {
		return
	}
	// A second Logger on the same file. If the daemon is running, both continue
	// the chain from the same tail and the log FORKS: not tampering, and
	// `akasha logs --verify` reports it as a fork, but a fork all the same.
	// Refusing --offline while /health answers would remove it; that belongs
	// where --offline is validated, not here after the file is already back.
	l, err := audit.New(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ restored %s but could NOT write an audit record (%v).\n"+
			"    This access is unrecorded. Note it by hand if that matters to you.\n", path, err)
		return
	}
	defer l.Close()
	l.Emit(audit.Event{
		Action:         audit.ActionRetrieved,
		Category:       "EscrowedFile",
		Risk:           "critical",
		AgentID:        vault.IdentityCLI,
		IdentitySource: "server",
		ToolName:       "akasha_restore_offline",
		Task:           "offline escrow restore of " + path,
	})
}

// agentSessionName describes the session for the refusal above without
// pretending to more certainty than the environment gives.
func agentSessionName(id string) string {
	if id == "" {
		return "an agent session"
	}
	return "agent " + id
}
