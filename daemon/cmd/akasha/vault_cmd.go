package main

import (
	"fmt"
	"os"
	"path/filepath"

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
		dest := filepath.Join(os.Getenv("HOME"), "akasha-backup.akb")
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
		fmt.Printf("  It unlocks %s, which this backup does NOT contain. Put that file\n", dbPath)
		fmt.Println("  (copied from the old machine, with its -wal sibling if the daemon was")
		fmt.Println("  not stopped cleanly) in place before starting the daemon.")
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
