package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Vault key backup and recovery",
}

var vaultBackupCmd = &cobra.Command{
	Use:   "backup [path]",
	Short: "Back up the vault key (encrypted with a passphrase)",
	// The old wording — "this is the only thing needed to recover your
	// vault.db" — was read as "this is the only thing you need", and the move
	// it invites is the one that loses a vault: copy vault.db, leave the
	// write-ahead log behind, restore onto a machine with the key, find an
	// empty vault. The key half and the data half are both required, and the
	// data half is not one file unless something has checkpointed it.
	Long: `Writes an encrypted backup of the vault KEY.

It contains no credentials. It can only unlock a vault.db that you still have,
so recovery on another machine needs BOTH halves:

  1. this .akb file, plus its passphrase
  2. ~/.akasha/vault.db — the credentials themselves

Copying vault.db while the daemon is running is the way people lose a vault:
until the write-ahead log is folded in, almost every row of a normal-sized
vault lives in ~/.akasha/vault.db-wal and vault.db is an empty header. This
command folds it in before it prints the recovery instructions, and so does a
clean daemon shutdown. If you copy the vault by hand at any other moment, take
vault.db-wal with it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Inside the data directory, which is a denied island, rather than loose
		// in $HOME. A file at $HOME/akasha-backup.akb has to be masked by name,
		// and a name-based mask is the one this sandbox cannot hold: a bind
		// covers an inode, so an ordinary `mv -f` over the path defeats it. The
		// island covers whatever appears inside it, including a backup written
		// after the run started.
		dest := filepath.Join(filepath.Dir(dbPath), "backups", "akasha-backup"+".akb")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return err
		}
		if len(args) > 0 {
			dest = args[0]
		}
		fmt.Print("Enter passphrase to protect backup: ")
		pass, err := readPassphrase()
		if err != nil {
			return err
		}

		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		if err := vlt.BackupKey(dest, pass); err != nil {
			return err
		}

		// Fold the write-ahead log in before telling anyone to copy vault.db —
		// the advice below is only true once this has run, and this command is
		// precisely where a user is thinking about taking a copy. A failure is
		// not fatal to the key backup, which is already written; it only means
		// the data half is still two files, so say that instead of claiming
		// otherwise.
		walErr := vlt.Checkpoint()

		fmt.Printf("\n✓ Key backup saved: %s\n", dest)
		fmt.Println("  Store this in iCloud, 1Password, or a USB drive.")
		fmt.Println()
		fmt.Println("  This is the KEY ONLY — it holds no credentials and cannot rebuild a")
		fmt.Println("  vault on its own. Recovery needs both halves:")
		fmt.Printf("    1. %s  + the passphrase you just typed\n", dest)
		fmt.Printf("    2. %s  (the credentials)\n", dbPath)
		fmt.Println("  Neither half carries your provider templates — those come from the")
		fmt.Println("  installer, and without them a restored vault brokers nothing.")
		fmt.Println()
		if walErr != nil {
			fmt.Printf("  ⚠  %v\n", walErr)
			fmt.Printf("     Copy %s-wal alongside it, or the copy will be empty.\n", dbPath)
			return nil
		}
		fmt.Printf("  %s is complete as of now, so copying that one file is enough.\n",
			filepath.Base(dbPath))
		return nil
	},
}

var vaultRestoreForce bool

var vaultRestoreCmd = &cobra.Command{
	Use:   "restore <backup-file>",
	Short: "Restore the vault key from a backup",
	Long: `Puts the vault key from a backup file back into this machine's credential
store.

It refuses if a DIFFERENT key is already there, because overwriting one makes
the vault it belongs to permanently undecryptable — and a running daemon holds
its key in memory, so nothing looks wrong until the next restart. --force says
you know which key you are keeping.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter backup passphrase: ")
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		if err := vault.RestoreKey(dbPath, args[0], pass,
			vault.RestoreOptions{ReplaceExistingKey: vaultRestoreForce}); err != nil {
			return err
		}
		fmt.Println("\n✓ Vault key restored.")
		fmt.Print(restoreNextSteps(dbPath, template.ShippedDir()))
		return nil
	},
}

var vaultRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the vault encryption key (re-encrypts all entries)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Key rotation is not yet implemented — coming in a future release.")
		fmt.Println("For now, run `akasha vault backup` to protect your current key.")
		return nil
	},
}

// restoreNextSteps says what a restored KEY still does not give you.
//
// A backup holds the key and nothing else, and the two missing pieces fail very
// differently. A missing vault.db is loud. Missing provider templates are not:
// the daemon starts, `akasha status` is green, and every brokered call then
// fails with `no template for provider "..."` — a symptom that arrives later,
// somewhere else, and looks like a different bug entirely. Nothing in the
// restore path mentioned them, so this is the moment to.
//
// Split out from RunE so the branch that matters can be tested. The "already
// here" case is not decoration: telling someone to go and find a directory they
// already have is how a recovery procedure loses its credibility.
func restoreNextSteps(dbPath, shippedDir string) string {
	var b strings.Builder
	// The wording tracks `akasha vault backup`, which calls the key and the
	// database "both halves". Saying "three things" here instead would have the
	// two commands disagree on the count, in a procedure people follow while
	// already anxious — and a recovery story that contradicts itself is one they
	// stop believing halfway through.
	fmt.Fprintln(&b, "\n  That was the KEY half. Recovery needs the other half too, and a working")
	fmt.Fprintln(&b, "  install needs one more thing that is not part of the vault at all:")
	fmt.Fprintf(&b, "\n  1. %s — the other half, the credentials themselves.\n", dbPath)
	fmt.Fprintln(&b, "     Copy it from the old machine, with its -wal sibling if the daemon was")
	fmt.Fprintln(&b, "     not stopped cleanly, before starting the daemon.")

	present := 0
	if ents, err := os.ReadDir(shippedDir); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				present++
			}
		}
	}
	if present > 0 {
		fmt.Fprintf(&b, "\n  2. Provider templates — already here (%d in %s).\n", present, shippedDir)
		fmt.Fprintln(&b, "     Not in the backup and not in the vault; they come from the installer.")
	} else {
		fmt.Fprintf(&b, "\n  2. Provider templates — MISSING from %s.\n", shippedDir)
		fmt.Fprintln(&b, "     Not in the backup and not in the vault; they come from the installer.")
		fmt.Fprintln(&b, "     Without them the daemon starts and `akasha status` looks healthy, but")
		fmt.Fprintln(&b, "     every brokered call fails with `no template for provider \"...\"`.")
		fmt.Fprintln(&b, "     Re-run the installer, or copy the directory from the old machine.")
	}
	return b.String()
}
