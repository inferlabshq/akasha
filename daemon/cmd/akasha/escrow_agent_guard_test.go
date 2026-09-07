package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// The commands that put an escrowed plaintext back on disk must refuse an agent
// session.
//
// `akasha uninstall` was the widest hole in escrow, and it did not look like one
// because of its name. From inside any agent session it opened the vault with
// escrow.Direct and wrote every file `protect` had ever taken back onto disk:
//
//   - no prompt        — the confirmation is gated on --purge (uninstall.go:116)
//   - no agent check   — protect and discover carried one; uninstall did not
//   - no cli.key       — escrow.Direct opens the database, not the socket
//   - no escrow gate   — that gate lives in the daemon, which is never called
//   - no audit record  — internal/vault does not import internal/audit
//
// and it deconfigured the user's MCP clients on the way out. protect's whole
// promise is that an agent running as you cannot get the plaintext back. One
// command it was allowed to run undid that.
//
// The assertion is on the ESCROWED FILE, not on the error text: a guard that
// returns an error while the stub has already been overwritten has not stopped
// anything.
func TestUninstallAndRestoreRefuseAnAgentSession(t *testing.T) {
	// A real escrowed file, so a guard that fails open leaves evidence.
	stage := func(t *testing.T) (dataDir, secretFile string) {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home)
		dataDir = filepath.Join(home, ".akasha")
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			t.Fatal(err)
		}
		v, err := vault.Open(filepath.Join(dataDir, "vault.db"), vault.Options{AllowNewVaultKey: true})
		if err != nil {
			t.Fatalf("open vault: %v", err)
		}
		defer v.Close()

		secretFile = filepath.Join(home, "secrets.env")
		if err := os.WriteFile(secretFile, []byte("API_TOKEN=the-only-copy\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := escrow.Protect(escrow.Direct{Vault: v}, secretFile); err != nil {
			t.Fatalf("protect: %v", err)
		}
		onDisk, _ := os.ReadFile(secretFile)
		if !escrow.IsStub(onDisk) {
			t.Fatal("protect left no stub; this test would prove nothing")
		}
		return dataDir, secretFile
	}

	for _, agentEnv := range []struct{ key, val string }{
		{"AKASHA_AGENT_ID", "claude-code"},
		{"AKASHA_AGENT_KEY", "agt_whatever"},
	} {
		t.Run("uninstall/"+agentEnv.key, func(t *testing.T) {
			dataDir, secretFile := stage(t)
			t.Setenv(agentEnv.key, agentEnv.val)
			withPaths(t, dataDir)

			err := uninstallCmd.RunE(uninstallCmd, nil)
			if err == nil {
				t.Fatal("uninstall ran from an agent session")
			}
			if !strings.Contains(err.Error(), "person at the keyboard") {
				t.Errorf("the refusal should hand off to the human, got: %v", err)
			}

			// The only assertion that matters: the plaintext did not come back.
			got, readErr := os.ReadFile(secretFile)
			if readErr != nil {
				t.Fatalf("the escrowed path is gone: %v", readErr)
			}
			if !escrow.IsStub(got) {
				t.Errorf("ESCROW BYPASS: the plaintext was restored to disk despite the refusal")
			}
			if strings.Contains(string(got), "the-only-copy") {
				t.Errorf("ESCROW BYPASS: the secret is on disk")
			}
			// And nothing else was torn down on the way to the refusal.
			if _, err := os.Stat(filepath.Join(dataDir, "vault.db")); err != nil {
				t.Errorf("the vault was touched before the refusal: %v", err)
			}
		})

		t.Run("restore/"+agentEnv.key, func(t *testing.T) {
			_, secretFile := stage(t)
			t.Setenv(agentEnv.key, agentEnv.val)

			err := restoreCmd.RunE(restoreCmd, []string{secretFile})
			if err == nil {
				t.Fatal("restore ran from an agent session")
			}
			got, _ := os.ReadFile(secretFile)
			if !escrow.IsStub(got) {
				t.Errorf("ESCROW BYPASS: restore put the plaintext back from an agent session")
			}
		})
	}

	// The control: with no agent identity in the environment, uninstall is
	// allowed to proceed and does restore the file. Without this, a guard that
	// refused unconditionally would pass every assertion above.
	t.Run("control: a human session still restores", func(t *testing.T) {
		dataDir, secretFile := stage(t)
		os.Unsetenv("AKASHA_AGENT_ID")
		os.Unsetenv("AKASHA_AGENT_KEY")
		withPaths(t, dataDir)

		if err := uninstallCmd.RunE(uninstallCmd, nil); err != nil {
			t.Fatalf("a human uninstall must work: %v", err)
		}
		got, err := os.ReadFile(secretFile)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if escrow.IsStub(got) {
			t.Error("the human path did not restore the escrowed original")
		}
		if string(got) != "API_TOKEN=the-only-copy\n" {
			t.Errorf("not restored byte-for-byte, got %q", got)
		}
	})
}

// withPaths points the command's package-level path flags at this test's dirs.
func withPaths(t *testing.T, dataDir string) {
	t.Helper()
	od, ol, os_ := dbPath, logPath, socketPath
	t.Cleanup(func() { dbPath, logPath, socketPath = od, ol, os_ })
	dbPath = filepath.Join(dataDir, "vault.db")
	logPath = filepath.Join(dataDir, "audit.log")
	socketPath = filepath.Join(dataDir, "akasha.sock")
}
