package setup

import (
	"errors"
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

	// StopDaemon asks the running daemon to stop, and DaemonAlive reports
	// whether one is still answering.
	//
	// Both are supplied by the CLI rather than built here, because stopping the
	// daemon is an AUTHENTICATED request and the caller key lives with the
	// command layer. Injecting them also gives the tests a daemon that refuses
	// to die, which is the case this whole path exists for and the one no unit
	// test could otherwise construct.
	//
	// Nil means "no stop path available" — treated as a daemon that could not
	// be stopped, never as one that is not running.
	StopDaemon  func() error
	DaemonAlive func() bool
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

	// Which keychain entry belongs to this vault is read from metadata INSIDE
	// the database, so it has to be read while the handle is still open.
	//
	// It used to be read 78 lines below this, after the Close — so the lookup
	// failed every single time with "sql: database is closed", and the failure
	// was silent because the fallback was the SHARED legacy account name. Every
	// --purge therefore deleted `vault-mlkem-sk` no matter which vault it was
	// purging: orphaning the real key on a machine with one vault, and
	// destroying an older vault's key on a machine with two.
	//
	// The comment that used to sit at the old site had the right idea and the
	// wrong scope. It guarded against the DIRECTORY being gone, and the handle
	// closes long before the directory does.
	keyAccount := ""
	var keyAccountErr error
	if vlt != nil {
		keyAccount, keyAccountErr = vlt.KeychainAccount()
	}

	if vlt != nil {
		vlt.Close() // release the DB handle before removing files
	}

	// ── Stop & deregister the daemon. ──
	//
	// The answer is carried all the way to the last line: a daemon that is
	// still running means this uninstall did not happen, however much of the
	// data is gone, and saying otherwise is the failure being fixed here.
	aliveFn := opts.DaemonAlive
	if aliveFn == nil {
		aliveFn = func() bool { return false }
	}
	hadService := serviceWasPresent(opts, aliveFn)
	daemonStopped := stopDaemon(opts)

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
			return verdict(daemonStopped, func() {
				fmt.Println("Daemon deregistered. Vault data left intact at")
				fmt.Printf("  %s\n", shorten(opts.DataDir))
				fmt.Println("Finish the manual config cleanup above before running with --purge.")
			})
		}
		return verdict(daemonStopped, func() {
			// Say what was actually there. Running this in an account where
			// setup had failed produced "Daemon deregistered ... Vault data
			// left intact at ~/.akasha" over no service and no such directory
			// — which is worse than useless to someone trying to work out
			// whether they still have a vault.
			switch {
			case hadService:
				fmt.Println("Daemon deregistered and agent configs cleaned.")
			default:
				fmt.Println("No daemon or service registration was found; agent configs cleaned.")
			}
			if dbExisted {
				fmt.Println("Vault data left intact at")
				fmt.Printf("  %s\n", shorten(opts.DataDir))
				fmt.Println("Re-run `akasha setup` to reactivate, or `akasha uninstall --purge` to")
				fmt.Println("delete the vault and keychain key as well.")
			} else {
				fmt.Printf("There was no vault at %s, so nothing was left behind.\n", shorten(opts.DBPath))
			}
		})
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
	// keyAccount was captured above, while the database was still open.
	keyKept := false
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
		keyKept = true
		fmt.Println("  • keychain key KEPT — this vault could not be opened, so akasha cannot")
		fmt.Println("    confirm the machine's key belongs to it. Remove it by hand if you are")
		fmt.Println("    sure no other vault needs it.")
	case keyAccountErr != nil:
		keyKept = true
		// Which entry belongs to this vault is read from metadata inside the
		// database. When that read fails the answer used to default to the
		// SHARED legacy account name, which on a machine with an older vault is
		// that vault's key — deleted here, permanently, while reporting success.
		fmt.Printf("  • keychain key KEPT — could not determine which entry belongs to this\n"+
			"    vault (%v). Refusing to guess: the fallback name may be another vault's\n"+
			"    key. Remove it by hand if you are sure no other vault needs it.\n", keyAccountErr)
	default:
		if err := vault.DeleteKeychainAccount(keyAccount); err != nil {
			keyKept = true
			fmt.Printf("  ✗ keychain key: %v\n", err)
		} else {
			fmt.Printf("  ✓ keychain key removed (%s)\n", keyAccount)
		}
	}
	fmt.Println()
	if len(stranded) > 0 {
		return verdict(daemonStopped, func() {
			fmt.Println("Akasha data removed, but the client configs listed above still reference")
			fmt.Println("it. Edit them before deleting the binary, or those sessions will start")
			fmt.Println("with an empty git/AWS configuration.")
		})
	}
	return verdict(daemonStopped, func() {
		if keyKept {
			// Saying "fully removed" over a key still sitting in the keychain is
			// the same false completion this file has been corrected for twice.
			fmt.Println("Akasha data removed, but the vault key is STILL in this machine's")
			fmt.Println("keychain — see the note above for why it was not deleted. Nothing else")
			fmt.Println("references it, so it is inert; remove it by hand once you are sure no")
			fmt.Println("other vault needs it.")
			return
		}
		fmt.Println("Akasha fully removed. The binary itself can now be deleted.")
	})
}

// verdict is the single place uninstall is allowed to say what it did.
//
// Every exit goes through it, because the claim and the fact were previously
// decided in different places: `stopDaemon` learned the daemon was still alive,
// and four separate return sites went on to print "Daemon deregistered" or
// "Akasha fully removed" regardless. A success message that a function other
// than the one doing the work is free to print is a message that will
// eventually be wrong.
func verdict(daemonStopped bool, success func()) error {
	if daemonStopped {
		success()
		return nil
	}
	fmt.Println("Akasha is NOT fully removed: the daemon is still running.")
	fmt.Println()
	fmt.Println("It is still holding the vault it had open and will keep answering any")
	fmt.Println("agent key issued before now — including on 127.0.0.1:7743, which survives")
	fmt.Println("a reinstall and would let a later MCP call reach the vault you just")
	fmt.Println("removed. Stop it before deleting the binary:")
	fmt.Println()
	fmt.Println("    akasha stop")
	fmt.Println("    # if that cannot reach it:")
	fmt.Println("    pkill -f 'akasha start'      # or: lsof -i :7743")
	fmt.Println()
	return errors.New("uninstall incomplete: the daemon is still running")
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

// stopDaemon stops the daemon and reports whether it is actually gone.
//
// It used to be deregisterDaemon: one `systemctl --user disable --now akasha`
// whose exit status was DISCARDED, followed by an unconditional unlink of the
// socket. On a machine with no working systemd user manager — the machine
// `setup` tells you to run `akasha start` on yourself — that combination
// reported a deregistration it had not performed and then deleted the one file
// that would have shown the daemon was still there. See shutdown.go.
//
// The order is deliberate. Ask the daemon first, because that is the only stop
// that drains in-flight requests and checkpoints the write-ahead log; the init
// system is the fallback for a daemon that is not answering, and it is asked
// second so a machine that has both still gets the clean stop.
// found reports whether there was anything to deregister at all: a live daemon,
// or a service registration on disk. Without it uninstall announced a
// deregistration it had not performed, on a machine where akasha was never
// installed.
func serviceWasPresent(opts UninstallOptions, alive func() bool) bool {
	if alive() {
		return true
	}
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat(filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "dev.akasha.daemon.plist"))
		return err == nil
	case "linux":
		_, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "akasha.service"))
		return err == nil
	}
	return false
}

func stopDaemon(opts UninstallOptions) (stopped bool) {
	alive := opts.DaemonAlive
	if alive == nil {
		alive = func() bool { return false }
	}

	if alive() && opts.StopDaemon != nil {
		if err := opts.StopDaemon(); err != nil {
			fmt.Printf("  ✗ the daemon refused the stop request: %v\n", err)
		}
	}

	// The init system, for a daemon that never answered and to remove the unit
	// so it does not come back at next login.
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

	if alive() {
		fmt.Println("  ✗ the daemon is STILL RUNNING and still holding the vault.")
		// The socket is deliberately LEFT IN PLACE. Removing it does not stop
		// the process; it only removes the thing a person would look at to
		// notice the process is there — and `akasha stop` needs it to try
		// again.
		return false
	}

	os.Remove(opts.SocketPath)
	return true
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
