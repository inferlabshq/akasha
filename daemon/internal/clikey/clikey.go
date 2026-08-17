// Package clikey provisions and locates the local CLI's own agent key.
//
// # Why the CLI needs a key at all
//
// Akasha used to infer the human from the ABSENCE of an agent key: a request
// carrying no X-Akasha-Key was taken to be the trusted local CLI, and was
// granted things a verified agent was refused — notably raw secret delivery
// into environment variables, and starting an `akasha run`.
//
// That made authentication REDUCE privilege, with two consequences:
//
//   - `akasha agent revoke` was not enforcement. An agent whose key was revoked
//     got everything back — and more than it had — by dropping the header. The
//     rational move for any local process was never to authenticate.
//   - The privileged path was the one requiring no credential, so there was
//     nothing to steal, nothing to revoke, and nothing to audit.
//
// Giving the CLI a real identity makes privilege monotonic in authentication:
// presenting less can only ever get you less. A caller with a revoked key that
// drops the header lands on the keyless floor, which the daemon refuses
// outright, rather than being promoted to the human.
//
// # What this is not
//
// The key file is readable by the user's own uid, and agents run as that same
// uid — so a determined local process can still read it and impersonate the
// CLI. That is the same-UID ceiling described in
// docs/design/same-user-identity.md, and it is unchanged by this package. What
// changes is that impersonation now requires stealing a specific, separately
// revocable credential, instead of being the reward for sending one fewer
// header. Real enforcement needs peer attestation or the sandbox — rungs 1 and
// 3 of that note.
package clikey

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// FileName is the CLI key's filename within the akasha data directory.
const FileName = "cli.key"

// Path returns the CLI key file for the data directory holding dbPath.
//
// It is derived from the vault path rather than from $HOME so that a daemon
// started with --db against a scratch vault gets its own CLI key. Sharing one
// key across vaults would let a throwaway daemon hand out an identity the real
// vault also honours.
func Path(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), FileName)
}

// Minter is the slice of *vault.Vault this package needs. Narrowing it keeps
// provisioning testable without standing up a keychain-backed vault, and states
// plainly that this package mints and verifies — it does not touch secrets.
type Minter interface {
	VerifyAgentKey(plaintext string) (string, error)
	MintReservedAgentKey(agentID string) (keyID, plaintext string, err error)
}

// Ensure returns a live CLI key for this vault, minting and persisting one if
// the file is missing or the key it holds is no longer good.
//
// The daemon calls this at startup, before it serves anything, so the CLI always
// has an identity to present — including on a fresh install where `akasha setup`
// has never run. Provisioning belongs to the daemon because minting needs the
// vault, and the vault is the daemon's to open.
//
// Re-minting on a stale file is deliberate. If the vault was rebuilt, or the CLI
// key was revoked, the human must still be able to reach their own daemon on
// their own machine; the key is an identity, not a containment boundary. Agent
// keys are the opposite and are never re-admitted automatically — see
// vault.RegisterAgentKey.
func Ensure(v Minter, path string) (string, error) {
	if key, err := read(path); err == nil && key != "" {
		if id, verr := v.VerifyAgentKey(key); verr == nil && id == vault.IdentityCLI {
			return key, nil
		}
		// Anything else — revoked, unknown after a vault rebuild, or a file
		// carrying some other agent's key — is replaced rather than trusted.
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read cli key %s: %w", path, err)
	}

	_, key, err := v.MintReservedAgentKey(vault.IdentityCLI)
	if err != nil {
		return "", fmt.Errorf("mint cli key: %w", err)
	}
	if err := write(path, key); err != nil {
		return "", err
	}
	return key, nil
}

// Load reads the CLI key for a CLI invocation. A missing file is not an error
// worth decorating here — the caller falls back to sending no key, and the
// daemon's own 401 explains the situation better than a client-side guess
// could, because only the daemon knows whether it is running.
func Load(path string) string {
	key, err := read(path)
	if err != nil {
		return ""
	}
	return key
}

func read(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// write persists the key 0600, replacing any existing file atomically so a
// concurrent CLI never reads a half-written key and gets a spurious 401.
func write(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), FileName+".*")
	if err != nil {
		return fmt.Errorf("write cli key: %w", err)
	}
	defer os.Remove(tmp.Name())
	// Chmod before the content lands: CreateTemp is already 0600, but an
	// explicit mode keeps the guarantee from depending on that detail.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("write cli key: %w", err)
	}
	if _, err := tmp.WriteString(key + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("write cli key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write cli key: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write cli key: %w", err)
	}
	return nil
}
