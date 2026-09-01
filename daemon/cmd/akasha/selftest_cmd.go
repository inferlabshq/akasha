package main

import (
	"os"

	"github.com/spf13/cobra"
	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/daemon/internal/sandbox"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// sandboxSelfTestCmd is the child half of the sandbox self-test.
//
// Hidden because it is not a user-facing operation: `akasha run` forks it inside
// the profile it is about to use, to prove the profile is actually enforced
// before launching the real agent.
//
// It takes no flags. The probe plan arrives on STDIN, because argv and the
// environment are readable by any same-user process — and that plan enumerates
// exactly the paths being protected.
var sandboxSelfTestCmd = &cobra.Command{
	Use:    "sandbox-selftest",
	Short:  "Internal: verify the sandbox is enforcing (reads a plan from stdin)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return sandbox.RunSelfTestChild(os.Stdin, os.Stdout, keyring.Get)
	},
}

func init() {
	// Point the self-test at the SAME keychain item the vault reads. Guessing
	// the names would let the probe pass while the real key stayed reachable.
	// Resolved lazily, from THIS vault's database: with per-vault keychain
	// accounts the item to probe depends on which vault is in play, and probing
	// the wrong one would come back "not found" and pass for the wrong reason.
	sandbox.SetKeychainProbeTarget(func() (string, string) {
		return vault.KeychainProbeFor(dbPath)
	})
	// And the reader, so the probe is only run when there is an item to read.
	sandbox.SetKeychainProbeReader(keyring.Get)
}
