package setup

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/internal/template"
)

// Load the in-repo curated template bundle so setup tests can render agent
// blocks from the real aws/github templates. The full-path override means the
// per-test HOME changes don't affect which providers load.
//
// After the run, delete the per-PID isolated keychain entries any real
// vault.Open created (see keyringService auto-isolation in vault.go), so test
// runs don't leave "akasha-test-*" entries behind.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()
	code := m.Run()
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.Exit(code)
}
