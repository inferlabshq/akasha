package server_test

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// TestMain loads the in-repo template bundle (assume resolves a template per
// provider) and cleans up the per-PID isolated keychain entry the vault creates
// under test (vault.go auto-isolates the keychain service when running as a
// test binary), so server test runs don't leave "akasha-test-*" entries behind.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()
	code := m.Run()
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.Exit(code)
}
