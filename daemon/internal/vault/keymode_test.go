package vault

import (
	"strings"
	"testing"
)

// A vault opened with a passphrase records that fact, so opening it WITHOUT one
// later is a sentence rather than an authentication failure on the first entry.
//
// That distinction is the point. "Wrong key" reads like a corrupt vault, and the
// obvious response to a corrupt vault is `akasha vault restore` — the one action
// that could actually destroy the data.
func TestPassphraseModeIsRecordedAndEnforced(t *testing.T) {
	v := openTestVault(t)
	if v.KeyModeOf() != KeyModeKeychain {
		t.Fatalf("a fresh vault reports mode %q, want %q", v.KeyModeOf(), KeyModeKeychain)
	}
	if v.RequiresPassphrase() {
		t.Fatal("a keychain-only vault claims to require a passphrase")
	}

	if err := v.setKeyMode(KeyModeKeychainPassphrase); err != nil {
		t.Fatal(err)
	}
	if !v.RequiresPassphrase() {
		t.Fatal("the recorded mode was not read back")
	}

	// And the refusal names the right recovery, never the destructive one.
	err := errPassphraseRequired("/home/dev/.akasha/store")
	for _, want := range []string{"--passphrase", "prompted", "NOT the fix"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal is missing %q: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "not a damaged vault") {
		t.Error("the refusal does not rule out corruption, which is what it will be mistaken for")
	}
}

// An unrecorded mode is keychain — which is every vault created before this
// existed, so an upgrade must not start demanding a passphrase nobody set.
func TestUnrecordedModeIsKeychain(t *testing.T) {
	v := openTestVault(t)
	if got := v.KeyModeOf(); got != KeyModeKeychain {
		t.Errorf("mode = %q, want %q for a vault with no recorded mode", got, KeyModeKeychain)
	}
	if v.RequiresPassphrase() {
		t.Error("an existing vault would refuse to open after an upgrade")
	}
}
