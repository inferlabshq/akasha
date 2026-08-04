package main

import (
	"fmt"
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Load the in-repo curated template bundle so `akasha template` command tests
// can explain/validate against the real shipped providers, and remove the
// per-PID keychain entry the vault creates under test.
//
// Tests here open a vault, and vault.keyringService auto-isolates test binaries
// to "akasha-test-<pid>" so they cannot clobber the real daemon key. Nothing
// reclaims those entries afterwards, though, so every `go test ./...` left one
// more ML-KEM key in the login keychain — 54 had accumulated before this was
// noticed. internal/vault, internal/server and internal/setup already do this;
// this package opened a vault without it.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()
	code := m.Run()
	svc := fmt.Sprintf("akasha-test-%d", os.Getpid())
	keyring.Delete(svc, "vault-mlkem-sk")
	keyring.Delete(svc, "vault-key")
	os.Exit(code)
}
