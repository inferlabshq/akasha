package setup

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// UninstallOptions controls how far `akasha uninstall` goes.
type UninstallOptions struct {
	DataDir    string // ~/.akasha (holds vault.db, audit.log, sockets)
	DBPath     string // vault.db
	LogPath    string // audit.log
	SocketPath string // unix socket

	// Purge also deletes the vault data and the OS-keychain key — the
	// destructive path that makes secrets unrecoverable. Without it, uninstall
	// only stops/deregisters the daemon and leaves data in place.
	Purge bool

	// Yes skips the interactive confirmation before a purge.
	Yes bool

	// ExportDir, if set, writes a self-contained restorable bundle (a copy of
	// vault.db plus a passphrase-protected key backup) here before anything is
	// removed. Recommended before --purge.
	ExportDir string
}

// openVaultForUninstall is a test seam. Uninstall tests fake $HOME to build an
// isolated machine, but a real vault.Open under a faked HOME blocks inside the
// OS keychain subprocess — so tests pre-open the vault under the real HOME and
// inject the handle here. Production always uses the real vault.Open.
var openVaultForUninstall = func(dbPath string) (*vault.Vault, error) {
	return vault.Open(dbPath, vault.Options{})
}

// Uninstall reverses `akasha setup`: it stops and deregisters the daemon and,
// when asked, removes the vault data and keychain key. It is deliberately
// conservative — the default leaves all secret material untouched so an
// accidental run can never destroy the vault.
func Uninstall(opts UninstallOptions) error {
	fmt.Println("Akasha uninstall")
	fmt.Println()

	// Sampled BEFORE the open, because vault.Open creates the database it was
	// asked for. See purgeGuard.
	_, dbStatErr := os.Stat(opts.DBPath)
	dbExisted := dbStatErr == nil

	vlt, vErr := openVaultForUninstall(opts.DBPath)
	if vErr != nil {
		// A locked/missing vault shouldn't block deregistration; just note it.
		fmt.Printf("  note: could not open vault (%v) — continuing\n", vErr)
		fmt.Println("  note: if any files were escrowed with `akasha protect`, they cannot be")
		fmt.Println("        restored without the vault — recover it first (akasha vault restore)")
	}

	// ── Warn about irreplaceable secrets before doing anything destructive. ──
	if opts.Purge && vlt != nil {
		if paths, err := escrow.List(escrow.Direct{Vault: vlt}); err == nil && len(paths) > 0 {
			fmt.Printf("ℹ  %d escrowed file(s) will be restored to disk before the purge:\n", len(paths))
			for _, p := range paths {
				fmt.Printf("     %s\n", shorten(p))
			}
			fmt.Println()
		}
		if n, err := vlt.CountNonDiscovered(); err == nil && n > 0 {
			fmt.Printf("⚠  %d agent-stored secret(s) live ONLY in this vault.\n", n)
			fmt.Println("   These were wrapped by an agent and have no copy at any original source —")
			fmt.Println("   purging the vault destroys them permanently. Discovered AWS/SSH/Git")
			fmt.Println("   credentials are safe: re-run `akasha discover` after reinstalling.")
			fmt.Println()
			if opts.ExportDir == "" {
				fmt.Println("   Strongly recommended: re-run with --export <dir> to save a restorable copy.")
				fmt.Println()
			}
		}
	}

	// ── Optional export of a restorable bundle. ──
	if opts.ExportDir != "" {
		if vlt == nil {
			return fmt.Errorf("--export requested but the vault could not be opened")
		}
		if err := exportBundle(vlt, opts.DBPath, opts.ExportDir); err != nil {
			return fmt.Errorf("export: %w", err)
		}
	}

	// ── Confirm before a purge. ──
	if opts.Purge && !opts.Yes {
		if !confirm(fmt.Sprintf("Permanently delete %s and the keychain key?", shorten(opts.DataDir))) {
			fmt.Println("Aborted — nothing removed.")
			if vlt != nil {
				vlt.Close()
			}
			return nil
		}
	}

	// ── Put escrowed originals back on disk. Runs on BOTH paths: a default
	//    uninstall must leave the machine as `akasha protect` found it, and a
	//    purge is about to destroy the only copy. Confirmed-purge ordering
	//    matters: restore happens after the confirmation (an aborted purge
	//    changes nothing) and before the data dir is removed. ──
	if vlt != nil {
		restoreEscrowed(vlt)
	}

	if vlt != nil {
		vlt.Close() // release the DB handle before removing files
	}

	// ── Stop & deregister the daemon. ──
	deregisterDaemon(opts.SocketPath)

	// ── Remove the akasha integration from every MCP client (the inverse of
	//    setup's config + env injection). Safe: only namespaced akasha entries
	//    are touched; all other servers and env vars are preserved. ──
	stranded := deconfigureMCPClients()
	if len(stranded) > 0 {
		fmt.Println()
		fmt.Println("!  Some client configs still point at akasha and could not be edited.")
		fmt.Println("   Agent sessions using them will break — the variables name paths that")
		fmt.Println("   are about to stop existing. Clean these up by hand:")
		for _, s := range stranded {
			fmt.Printf("     %s\n", s)
		}
	}

	if !opts.Purge {
		fmt.Println()
		if len(stranded) > 0 {
			fmt.Println("Daemon deregistered. Vault data left intact at")
			fmt.Printf("  %s\n", shorten(opts.DataDir))
			fmt.Println("Finish the manual config cleanup above before running with --purge.")
			return nil
		}
		fmt.Println("Daemon deregistered and agent configs cleaned. Vault data left intact at")
		fmt.Printf("  %s\n", shorten(opts.DataDir))
		fmt.Println("Re-run `akasha setup` to reactivate, or `akasha uninstall --purge` to")
		fmt.Println("delete the vault and keychain key as well.")
		return nil
	}

	// ── Purge: remove the data directory (which holds vault.db and its KEM
	//    ciphertext) BEFORE the keychain key. Order matters for crash-safety:
	//    if this is interrupted between the two steps, the surviving half-state
	//    must be the safe one. Removing the DB first means a failure leaves an
	//    orphaned keychain key with no data (harmless — the next setup treats it
	//    as fresh). The reverse order — key gone, DB rows surviving — is the
	//    silent-orphan corruption the resolveKeys guard exists to catch, so we
	//    never deliberately create it. ──
	// Prove this directory is ours before deleting it, and prove the machine's
	// keychain key is ours before removing that. Both follow from the vault
	// having opened — see purgeguard.go.
	// Captured before the directory goes: the account name is derived from
	// metadata inside the database, and a key deleted on the strength of a
	// lookup against a removed database would be a guess.
	keyAccount := ""
	if vlt != nil {
		keyAccount = vlt.KeychainAccount()
	}
	if err := purgeGuard(opts.DataDir, opts.DBPath, dbExisted); err != nil {
		if vlt != nil {
			vlt.Close()
		}
		return err
	}
	if err := os.RemoveAll(opts.DataDir); err != nil {
		return fmt.Errorf("remove %s: %w", opts.DataDir, err)
	}
	fmt.Printf("  ✓ removed %s\n", shorten(opts.DataDir))
	// The keychain entry is MACHINE-global — one per install, not one per vault
	// — so this is a different question from "may I delete the directory", and
	// it needs a stronger answer. Deleting it for a vault that never opened
	// could take the key another vault still needs, and that vault's owner
	// would find out at their next startup with no idea why.
	//
	// The vault having opened is the only proof available that the key on this
	// machine is the one belonging to it.
	switch {
	case vlt == nil:
		fmt.Println("  • keychain key KEPT — this vault could not be opened, so akasha cannot")
		fmt.Println("    confirm the machine's key belongs to it. Remove it by hand if you are")
		fmt.Println("    sure no other vault needs it.")
	default:
		if err := vault.DeleteKeychainAccount(keyAccount); err != nil {
			fmt.Printf("  ✗ keychain key: %v\n", err)
		} else {
			fmt.Printf("  ✓ keychain key removed (%s)\n", keyAccount)
		}
	}
	fmt.Println()
	if len(stranded) > 0 {
		fmt.Println("Akasha data removed, but the client configs listed above still reference")
		fmt.Println("it. Edit them before deleting the binary, or those sessions will start")
		fmt.Println("with an empty git/AWS configuration.")
		return nil
	}
	fmt.Println("Akasha fully removed. The binary itself can now be deleted.")
	return nil
}

// restoreEscrowed writes every `akasha protect`-escrowed original back to
// disk, byte-for-byte. Failures are reported per-file and never abort the
// uninstall — but on the purge path the caller has already listed these
// files, so nothing disappears silently.
func restoreEscrowed(vlt *vault.Vault) {
	v := escrow.Direct{Vault: vlt}
	paths, err := escrow.List(v)
	if err != nil || len(paths) == 0 {
		return
	}
	for _, p := range paths {
		if err := escrow.Restore(v, p); err != nil {
			fmt.Printf("  ✗ restore %s: %v — recover manually with `akasha restore %s` before purging\n",
				shorten(p), err, p)
			continue
		}
		fmt.Printf("  ✓ restored escrowed original %s\n", shorten(p))
	}
}

// readExportPassphrase is a test seam. The real reader needs a terminal, and
// the refusal it produces without one is itself a behaviour worth pinning.
var readExportPassphrase = promptPassphrase

// exportBundle writes a restorable pair into dir: a copy of vault.db with its
// write-ahead log folded in, and a passphrase-protected key backup. Together
// they can be restored later with `akasha vault restore` + the copied DB.
//
// Everything that can refuse happens BEFORE the first byte is written. The
// order used to be the other way round — copy the DB, then ask for a
// passphrase — so a non-interactive run, which is how anyone scripts an
// uninstall, left a vault.db in the target directory, no key backup, and an
// aborted uninstall. A half-written bundle is worse than no bundle: it looks
// like a backup, and it is only opened on the day it is needed.
func exportBundle(vlt *vault.Vault, dbPath, dir string) error {
	pass := readExportPassphrase("Passphrase to encrypt the exported key backup: ")
	if len(pass) == 0 {
		return fmt.Errorf("a passphrase is required to encrypt the exported key, and this session has\n" +
			"  no terminal to type one into. Nothing was written.\n" +
			"  Run the same command from a terminal, or take the two halves by hand first:\n" +
			"    akasha vault backup <dir>/akasha-backup.akb\n" +
			"    cp ~/.akasha/vault.db <dir>/")
	}

	// The vault is open, so in WAL mode almost every row of a normal-sized
	// vault is still in vault.db-wal and vault.db itself is a 4 KB header.
	// Copying it as-is is what made the exported bundle contain zero rows.
	// Refuse rather than write an empty database: an unrestorable bundle is
	// only discovered on the day someone needs it.
	if err := vlt.Checkpoint(); err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	dbCopy := filepath.Join(dir, "vault.db")
	akb := filepath.Join(dir, "akasha-backup.akb")
	if err := copyFile(dbPath, dbCopy, 0600); err != nil {
		return fmt.Errorf("copy vault.db: %w", err)
	}
	if err := vlt.BackupKey(akb, pass); err != nil {
		os.Remove(dbCopy)
		return fmt.Errorf("write key backup: %w", err)
	}

	fmt.Printf("  ✓ exported restorable bundle to %s\n", shorten(dir))
	fmt.Println("    Both files are needed: the .akb is the key, vault.db is the data.")
	fmt.Println("    Restore later with:")
	fmt.Printf("      akasha vault restore %s --db <new>/vault.db   # then copy vault.db back\n", shorten(akb))
	fmt.Println()
	return nil
}

// deregisterDaemon stops the running daemon and removes its OS service entry.
func deregisterDaemon(socketPath string) {
	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "dev.akasha.daemon.plist")
		exec.Command("launchctl", "unload", plist).Run()
		if err := os.Remove(plist); err == nil {
			fmt.Println("  ✓ launchd service removed")
		}
	case "linux":
		exec.Command("systemctl", "--user", "disable", "--now", "akasha").Run()
		unit := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "akasha.service")
		if err := os.Remove(unit); err == nil {
			fmt.Println("  ✓ systemd unit removed")
		}
	}
	os.Remove(socketPath)
}

// deconfigureMCPClients removes akasha's MCP server entry and injected session
// env from every client that has them, leaving the rest of each config intact.
// It returns one line per config it could NOT clean; the caller must surface
// those before removing anything and must not report a clean uninstall.
//
// Both steps are attempted for every client even when one of them fails: an
// unparseable mcp.json says nothing about that client's settings.json.
func deconfigureMCPClients() []string {
	var stranded []string
	for _, c := range mcpClients {
		var cleaned []string

		if changed, err := c.deconfigure(); err != nil {
			stranded = append(stranded, fmt.Sprintf("%s: %v", c.label, err))
		} else if changed {
			cleaned = append(cleaned, shorten(expand(c.cfgPath)))
		}

		if t := c.envTargetFor(); t != nil {
			if changed, err := removeAgentEnv(t); err != nil {
				stranded = append(stranded, fmt.Sprintf("%s: %v", c.label, err))
			} else if changed {
				cleaned = append(cleaned, shorten(expand(t.path)))
			}
		}

		if len(cleaned) > 0 {
			fmt.Printf("  ✓ %s: removed akasha config (%s)\n", c.label, strings.Join(cleaned, ", "))
		}
	}
	return stranded
}

// ─── small interactive helpers ────────────────────────────────────────────

func confirm(prompt string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive and no --yes: refuse the destructive action.
		fmt.Println("  (non-interactive session — pass --yes to confirm a purge)")
		return false
	}
	fmt.Printf("%s [y/N]: ", prompt)
	var resp string
	fmt.Scanln(&resp)
	return resp == "y" || resp == "Y" || resp == "yes"
}

func promptPassphrase(prompt string) []byte {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	fmt.Print(prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil
	}
	return pass
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
