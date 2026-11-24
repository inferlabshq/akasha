package setup

import (
	"fmt"
	"os"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Load the in-repo curated template bundle so setup tests can render agent
// blocks from the real aws/github templates. The full-path override means the
// per-test HOME changes don't affect which providers load.
//
// HOME is replaced for the whole package, not per test. A test that swaps
// mcpClients but not HOME still reaches the developer's real
// ~/.claude/settings.json, because envTargetFor names it by "~". The resync
// tests read that file and WROTE their placeholder key into it, so running this
// suite broke the credential access of the agent running it.
//
// After the run, delete the per-PID isolated keychain entries any real
// vault.Open created (see keyringService auto-isolation in vault.go), so test
// runs don't leave "akasha-test-*" entries behind.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", testHomePrefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("HOME", home)
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()
	code := m.Run()
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.RemoveAll(home)
	os.Exit(code)
}

const testHomePrefix = "akasha-setup-test-home"

// The guard for the above: every settings file a resync can write must sit
// under the throwaway home. It fails if HOME is left pointing at a real one.
func TestSetupTestsCannotReachARealHome(t *testing.T) {
	home := os.Getenv("HOME")
	if !strings.Contains(home, testHomePrefix) {
		t.Fatalf("setup tests are running with HOME=%s", home)
	}
	for _, c := range mcpClients {
		if et := c.envTargetFor(); et != nil && !strings.HasPrefix(expand(et.path), home) {
			t.Errorf("%s: %s is outside the test home", c.id, expand(et.path))
		}
	}
}
