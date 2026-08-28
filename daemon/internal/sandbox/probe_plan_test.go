package sandbox

import (
	"errors"
	"testing"
)

// The self-test can only ask the child "did your read succeed?", so a read that
// fails for ANY reason reads as a pass. On macOS `security` says "could not be
// found" both for a denied item and for one that does not exist — so on a host
// with no vault key the keychain half passed while proving nothing.
//
// That is the shape of green CI was about to be built on: three macOS versions
// all reporting the seatbelt rules still close the keychain, on runners that
// have no keychain item to close.
func TestKeychainProbeNeedsSomethingRealToRead(t *testing.T) {
	restoreTarget, restoreRead := keychainProbeTarget, keychainProbeRead
	t.Cleanup(func() { keychainProbeTarget, keychainProbeRead = restoreTarget, restoreRead })
	keychainProbeTarget = func() (string, string) { return "akasha-test", "vault-mlkem-sk" }

	// Absent — the fresh-machine and fresh-runner case.
	keychainProbeRead = func(string, string) (string, error) {
		return "", errors.New("The specified item could not be found in the keychain.")
	}
	if p := planProbe(Spec{DenyKeychain: true}); p.Keychain != nil {
		t.Error("planned a keychain probe against an item that cannot be read — " +
			"the child's failure to read it would then be reported as the sandbox working")
	}

	// Present — the only case where the answer means anything.
	keychainProbeRead = func(string, string) (string, error) { return "a-real-key", nil }
	p := planProbe(Spec{DenyKeychain: true})
	if p.Keychain == nil {
		t.Fatal("no keychain probe planned for an item that IS readable, so the deny is never checked")
	}
	if p.Keychain.Service != "akasha-test" || p.Keychain.Account != "vault-mlkem-sk" {
		t.Errorf("probing the wrong item: %+v — it must be the one the vault reads", p.Keychain)
	}
}

// DenyKeychain off means no probe, whatever the store holds.
func TestNoKeychainProbeWhenTheKeychainIsNotDenied(t *testing.T) {
	restoreTarget, restoreRead := keychainProbeTarget, keychainProbeRead
	t.Cleanup(func() { keychainProbeTarget, keychainProbeRead = restoreTarget, restoreRead })
	keychainProbeTarget = func() (string, string) { return "akasha-test", "vault-mlkem-sk" }
	keychainProbeRead = func(string, string) (string, error) { return "a-real-key", nil }

	if p := planProbe(Spec{DenyKeychain: false}); p.Keychain != nil {
		t.Error("planned a keychain probe for a spec that does not deny the keychain")
	}
}
