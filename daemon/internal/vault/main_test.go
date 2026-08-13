package vault_test

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// TestMain arranges a usable credential store, then cleans up after itself.
//
// The vault stores its ML-KEM key in the OS keychain, so every test that opens
// a vault needs one. A headless Linux CI runner has no Secret Service —
// "org.freedesktop.secrets was not provided by any .service files" — so every
// vault test failed there while passing on any developer's Mac. That is the
// worst shape for a test suite: green where it is written, red where it is
// gated, and easy to start ignoring.
//
// Where a real keyring exists it is used, because that is the path production
// takes and where the interesting failures live (the ACL breakage this project
// has hit twice). Where one does not, an in-memory mock stands in: the vault's
// keychain interaction is incidental to what these tests actually assert —
// crypto, storage, agent keys, backup and restore.
func TestMain(m *testing.M) {
	mocked := ensureKeyring()
	code := m.Run()
	if !mocked {
		// Per-PID isolated entries (see keyringService in vault.go) — remove
		// them so runs do not leave "akasha-test-*" behind.
		svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
		keyring.Delete(svc, "vault-mlkem-sk")
		keyring.Delete(svc, "vault-key")
	}
	os.Exit(code)
}

// ensureKeyring reports whether it had to substitute the in-memory mock.
//
// AKASHA_TEST_MOCK_KEYRING=1 forces the mock, so the headless path can be
// exercised on a machine that has a keyring. Without that, the branch CI
// actually runs is the one nobody can reproduce before pushing — which is how
// it stayed broken.
func ensureKeyring() bool {
	if os.Getenv("AKASHA_TEST_MOCK_KEYRING") == "1" {
		keyring.MockInit()
		return true
	}
	const probeSvc, probeAcct = "akasha-keyring-probe", "probe"
	if err := keyring.Set(probeSvc, probeAcct, "x"); err != nil {
		fmt.Fprintf(os.Stderr, "vault tests: no usable OS keyring (%v) — using an in-memory one\n", err)
		keyring.MockInit()
		return true
	}
	keyring.Delete(probeSvc, probeAcct)
	return false
}
