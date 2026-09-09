package server_test

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// testSessionBase is where every credential file this binary materializes has
// to land. TestMain owns it; tests assert containment against it.
var testSessionBase string

// TestMain loads the in-repo template bundle (assume resolves a template per
// provider) and cleans up the per-PID isolated keychain entry the vault creates
// under test (vault.go auto-isolates the keychain service when running as a
// test binary), so server test runs don't leave "akasha-test-*" entries behind.
//
// It also pins where /assume writes. A successful assume puts a LIVE PLAINTEXT
// credential on disk, and assume.Write picks the location itself — $XDG_RUNTIME_DIR,
// then /dev/shm, then ~/.akasha — so on a developer's Mac these tests wrote
// credential files straight into the real data directory. They did: an agent
// reproducing an assume call during a review left one in ~/.akasha/sessions,
// unnoticed because the tests that assume os.Remove the path they are handed
// without ever asking where it points.
//
// This belongs here rather than in newTestServer because SIX constructors in
// this package stand a server up — newTestServer, newPolicyTestServer,
// newPolicyTestServerDir, newRunTestServer, newSwappablePolicyServer and
// stoppableServer — and isolating inside one of them leaves five holes plus a
// false sense that the package is clean. Redirecting HOME instead is not
// available here: a real vault.Open resolves its keychain through $HOME on
// macOS, so these tests cannot move HOME and open a vault.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()

	base, err := os.MkdirTemp("", "akasha-server-sessions")
	if err != nil {
		panic("test session base: " + err.Error())
	}
	testSessionBase = base
	assume.SetSessionBase(base)

	code := m.Run()

	os.RemoveAll(base)
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.Exit(code)
}
