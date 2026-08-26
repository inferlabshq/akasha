package setup

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// GUARANTEE: setup refuses before it changes anything on a machine whose
// credential store cannot hold the vault key.
//
// `akasha setup --yes` on a headless Linux box wrote the systemd user unit,
// enabled it, and only then opened the vault — which failed on the keychain,
// exit 1. What it left behind was worse than nothing: a half-configured machine
// carrying a Restart=always unit looping into the same failure. The store is the
// one prerequisite setup cannot supply, so it has to be the first question.
//
// The registrar is replaced with a panic rather than a flag, and deliberately:
// if the check ever moves back below it, this test must stop setup dead there.
// Letting Run continue would put a launchd plist or a systemd unit on whatever
// machine is running the test suite, and then go on to scan the developer's home
// directory for credentials.
func TestSetupChecksCredentialStoreBeforeRegisteringAnything(t *testing.T) {
	preflight, registrar := credStorePreflight, daemonRegistrar
	t.Cleanup(func() { credStorePreflight, daemonRegistrar = preflight, registrar })

	storeBroken := errors.New("this machine's credential store could not be read (no dbus)")
	credStorePreflight = func() error { return storeBroken }
	daemonRegistrar = func(string, string, string) error {
		panic("setup registered a login service before checking the credential store")
	}

	dir := t.TempDir()
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%v", r)
			}
		}()
		return Run(filepath.Join(dir, "vault.db"), filepath.Join(dir, "audit.log"),
			filepath.Join(dir, "akasha.sock"), nil)
	}()

	if err == nil {
		t.Fatal("setup must fail when the vault key cannot be stored, not continue half-configured")
	}
	if !errors.Is(err, storeBroken) {
		t.Errorf("setup swallowed the credential-store cause, leaving nothing to act on: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot set up akasha") {
		t.Errorf("the failure does not say what it refused to do: %v", err)
	}
}
