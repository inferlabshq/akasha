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
	Long: `Writes an encrypted backup of the vault key. This is the only thing
needed to recover your vault.db on another machine. Store it safely.`,
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
		fmt.Printf("\n✓ Backup saved: %s\n", dest)
		fmt.Println("  Store this in iCloud, 1Password, or a USB drive.")
		fmt.Println("  You need this file + passphrase to recover your vault.")
		return nil
	},
}

var vaultRestoreCmd = &cobra.Command{
	Use:   "restore <backup-file>",
	Short: "Restore the vault key from a backup",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter backup passphrase: ")
		pass, err := readPassphrase()
		if err != nil {
			return err
		}
		if err := vault.RestoreKey(dbPath, args[0], pass); err != nil {
			return err
		}
		fmt.Println("\n✓ Vault key restored.")
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
