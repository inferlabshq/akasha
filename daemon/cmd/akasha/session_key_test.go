package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// sessionKeyEnv is the variable a harness session carries its agent key in.
const sessionKeyEnv = "AKASHA_AGENT" + "_KEY"

// The state that made `akasha status` useless: client configs sound, but the
// key THIS session presents was rotated out from under it. status only ever
// compared configs to the vault, so it reported healthy while every other
// command failed — and the failure text pointed at `resync --rotate`, which
// rewrites working configs and forces an IDE restart to fix nothing.
func TestStatusReportsAStaleSessionKey(t *testing.T) {
	vlt, err := vault.Open(filepath.Join(t.TempDir(), "v.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()

	keyID, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(sessionKeyEnv, key)

	// A live key says nothing — status stays quiet when there is no problem.
	var quiet bytes.Buffer
	reportSessionKey(&quiet, vlt, true)
	if quiet.Len() != 0 {
		t.Errorf("a valid session key should produce no output, got: %s", quiet.String())
	}

	// Revoked, configs sound: name the real cause and the real fix.
	if err := vlt.RevokeAgentKey(keyID); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reportSessionKey(&out, vlt, true)
	got := out.String()
	for _, want := range []string{"REVOKED", "configs are fine", "start a new session", "Do NOT run"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, key) {
		t.Error("status leaked the agent key itself")
	}

	// Configs ALSO broken: repairing those comes first, so do not tell the user
	// their configs are fine.
	var both bytes.Buffer
	reportSessionKey(&both, vlt, false)
	if strings.Contains(both.String(), "configs are fine") {
		t.Errorf("must not claim healthy configs when they are not:\n%s", both.String())
	}
}

// A key the vault has never seen is a desync, not a revocation, and the two
// have different repairs — so they must not be reported with the same words.
func TestStatusDistinguishesUnrecognisedFromRevoked(t *testing.T) {
	vlt, err := vault.Open(filepath.Join(t.TempDir(), "v.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()

	t.Setenv(sessionKeyEnv, "agt_claude_neverissued")
	var out bytes.Buffer
	reportSessionKey(&out, vlt, true)
	got := out.String()
	if !strings.Contains(got, "not recognised") {
		t.Errorf("an unknown key should read as a desync, got:\n%s", got)
	}
	if strings.Contains(got, "REVOKED") {
		t.Errorf("an unknown key is not a revoked key:\n%s", got)
	}
}

// An unset key is not a problem to report — the keyless path is a separate
// question, and status must not cry wolf in every plain shell.
func TestStatusSilentWhenNoSessionKey(t *testing.T) {
	vlt, err := vault.Open(filepath.Join(t.TempDir(), "v.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()

	t.Setenv(sessionKeyEnv, "")
	var out bytes.Buffer
	reportSessionKey(&out, vlt, true)
	if out.Len() != 0 {
		t.Errorf("no key set should mean no output, got: %s", out.String())
	}
}
