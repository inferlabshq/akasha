package vault_test

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// TestMain cleans up the per-PID isolated keychain entries the vault created
// under test (see keyringService auto-isolation in vault.go), so test runs
// don't leave "akasha-test-*" entries behind.
func TestMain(m *testing.M) {
	code := m.Run()
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.Exit(code)
}
