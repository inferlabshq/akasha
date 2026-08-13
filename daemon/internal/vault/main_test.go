package vault_test

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// TestMain removes the per-PID isolated keychain entries the vault creates under
// test (see keyringService in vault.go), so runs do not leave "akasha-test-*"
// behind on a developer's machine.
//
// Arranging a usable keyring is NOT done here: the vault does it for itself
// whenever it detects a test binary, because four packages open vaults and a
// per-package TestMain is four places to forget. On a host with no credential
// store these deletes are no-ops against the in-memory stand-in.
func TestMain(m *testing.M) {
	code := m.Run()
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.Exit(code)
}
