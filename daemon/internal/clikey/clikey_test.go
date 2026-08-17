package clikey

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// fakeVault is a Minter that records what it was asked to mint, so these tests
// assert on provisioning behaviour without a keychain-backed vault.
type fakeVault struct {
	// live maps a key to the identity it authenticates as.
	live  map[string]string
	mints int
	n     int
}

func newFake() *fakeVault { return &fakeVault{live: map[string]string{}} }

func (f *fakeVault) VerifyAgentKey(plaintext string) (string, error) {
	if id, ok := f.live[plaintext]; ok {
		return id, nil
	}
	return "", vault.ErrAgentKeyInvalid
}

func (f *fakeVault) MintReservedAgentKey(agentID string) (string, string, error) {
	f.mints++
	f.n++
	key := "agt_" + agentID + "_" + string(rune('a'+f.n))
	f.live[key] = agentID
	return "ak_" + key, key, nil
}

// revoke makes a previously minted key stop verifying, as RevokeAgentKey does.
func (f *fakeVault) revoke(key string) { delete(f.live, key) }

func TestEnsureMintsThenReusesTheSameKey(t *testing.T) {
	f, path := newFake(), filepath.Join(t.TempDir(), FileName)

	first, err := Ensure(f, path)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" {
		t.Fatal("Ensure returned an empty key")
	}
	if f.live[first] != vault.IdentityCLI {
		t.Errorf("key was minted for %q, want %q", f.live[first], vault.IdentityCLI)
	}

	// A restart must not churn the identity: an agent-keys registry that grows
	// a row per daemon start makes `akasha agent list` useless, and every
	// already-running CLI would be holding a superseded key.
	second, err := Ensure(f, path)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("Ensure re-minted on a healthy key: %q then %q", first, second)
	}
	if f.mints != 1 {
		t.Errorf("minted %d times, want 1", f.mints)
	}
}

// The key file must not be readable by other users. It is not a defence against
// same-uid processes — nothing at this layer is — but it must at least not be
// world-readable.
func TestEnsureWritesTheKey0600(t *testing.T) {
	f, path := newFake(), filepath.Join(t.TempDir(), FileName)
	if _, err := Ensure(f, path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("cli key mode %v, want 0600", perm)
	}
}

// A revoked or vault-rebuilt CLI key is replaced, not trusted. The human must
// always be able to reach their own daemon; the CLI key is an identity, not a
// containment boundary. (Agent keys are the opposite — RegisterAgentKey refuses
// to un-revoke one.)
func TestEnsureReplacesAKeyThatNoLongerVerifies(t *testing.T) {
	f, path := newFake(), filepath.Join(t.TempDir(), FileName)
	first, err := Ensure(f, path)
	if err != nil {
		t.Fatal(err)
	}
	f.revoke(first)

	second, err := Ensure(f, path)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Error("Ensure kept using a key the vault no longer accepts")
	}
	if f.live[second] != vault.IdentityCLI {
		t.Errorf("replacement key authenticates as %q, want %q", f.live[second], vault.IdentityCLI)
	}
	if got := Load(path); got != second {
		t.Errorf("the replacement was not persisted: file has %q, want %q", got, second)
	}
}

// A file holding some OTHER agent's key must not be accepted as the CLI's.
// Otherwise dropping an agent key into cli.key would promote that agent to the
// human — the same escalation this package exists to close, by a different
// route.
func TestEnsureRejectsAKeyBelongingToAnotherIdentity(t *testing.T) {
	f, path := newFake(), filepath.Join(t.TempDir(), FileName)
	_, impostor, err := f.MintReservedAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(impostor+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Ensure(f, path)
	if err != nil {
		t.Fatal(err)
	}
	if got == impostor {
		t.Fatal("a key belonging to agent \"claude\" was accepted as the CLI's identity")
	}
	if f.live[got] != vault.IdentityCLI {
		t.Errorf("key authenticates as %q, want %q", f.live[got], vault.IdentityCLI)
	}
}

// Load tolerates the trailing newline Ensure writes, and treats a missing file
// as "no key" rather than an error — the daemon's 401 explains the situation
// better than a client-side guess, because only the daemon knows it is running.
func TestLoadTrimsAndTolerAtesAMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if got := Load(path); got != "" {
		t.Errorf("missing file should Load as empty, got %q", got)
	}
	if err := os.WriteFile(path, []byte("  agt_cli_x \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Load(path); got != "agt_cli_x" {
		t.Errorf("Load = %q, want the trimmed key", got)
	}
}

// Path follows --db rather than $HOME, so a scratch daemon gets its own CLI
// key. Sharing one across vaults would let a throwaway daemon hand out an
// identity the real vault also honours.
func TestPathFollowsTheVaultDirectory(t *testing.T) {
	if got, want := Path("/tmp/scratch/vault.db"), filepath.Join("/tmp/scratch", FileName); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

// A read error that is NOT "file missing" must surface rather than being
// silently papered over with a fresh mint: if the data directory is unreadable,
// re-minting hides a real fault and leaves a key nobody can load.
func TestEnsureSurfacesAnUnreadableKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	// A directory where the file should be: reads fail with something other
	// than ErrNotExist.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(newFake(), path); err == nil {
		t.Error("Ensure silently recovered from an unreadable key file")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Errorf("wrong error surfaced: %v", err)
	}
}
