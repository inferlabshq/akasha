package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// withClaudeSession lays out BOTH files setup writes together: the MCP config
// (via the existing withClaudeConfig helper) and the harness settings file the
// agent's shell actually reads its key from.
//
// HOME is redirected because envTargetFor() resolves ~/.claude/settings.json —
// a test that did not would edit the developer's own settings file, which is a
// live config on the machine running the suite.
func withClaudeSession(t *testing.T, cfgKey, envKey string) (home, cfgPath string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)

	cfgPath = withClaudeConfig(t, fmt.Sprintf(
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude"],"env":{%q:%q}}}}`,
		agentKeyEnv, cfgKey))

	if envKey != "" {
		if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf(`{"env":{%q:%q,"AKASHA_AGENT_ID":"claude","AWS_CONFIG_FILE":"/should/survive"}}`,
			agentKeyEnv, envKey)
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return home, cfgPath
}

// configKey reads the key the MCP config now holds, so a test can assert the
// two files AGREE rather than assert a particular value the fake happens to
// mint.
func configKey(t *testing.T, cfgPath string) string {
	t.Helper()
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Env map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("mcp config is not JSON: %v", err)
	}
	return cfg.MCPServers["akasha"].Env[agentKeyEnv]
}

func sessionEnv(t *testing.T, home string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("settings.json: %v", err)
	}
	var got struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("settings.json is no longer JSON: %v", err)
	}
	return got.Env
}

// The bug as the property it violated: after ANY resync, the key the agent's
// session will present must still be one the vault accepts.
//
// Rotation wrote the new key to the MCP config and then revoked the key the
// settings file still held. The documented repair therefore killed every akasha
// CLI call from that session, and `status` reported the client healthy because
// nothing ever read the settings file.
func TestRotateLeavesTheSessionWithAWorkingKey(t *testing.T) {
	home, cfgPath := withClaudeSession(t, "old-key", "old-key")
	v := &fakeVault{valid: map[string]string{"old-key": "claude"}}

	res, err := ResyncClient(v, "akasha", "claude", true)
	if err != nil {
		t.Fatalf("resync --rotate: %v", err)
	}
	if !res.Rotated || !res.EnvUpdated {
		t.Errorf("rotate must report writing BOTH files: %+v", res)
	}

	// The invariant is that the two files AGREE. Asserting the env key merely
	// "verifies" would pass against a stub that registers everything it mints,
	// and the bug was never about validity in the abstract — it was the config
	// moving on while the session was left holding the retired value.
	env := sessionEnv(t, home)
	if got, want := env[agentKeyEnv], configKey(t, cfgPath); got != want {
		t.Errorf("settings key %q != config key %q — config repaired, environment "+
			"left behind, which is the desync", got, want)
	}
	if env[agentKeyEnv] == "old-key" {
		t.Error("the settings file still holds the superseded key")
	}
	if !v.revoked["old-key"] {
		t.Error("the superseded key was never retired — rotation must replace, not accumulate")
	}
	// Rotation is about the credential, not about the rest of the environment
	// that routes provider tooling through akasha.
	if env["AWS_CONFIG_FILE"] != "/should/survive" {
		t.Errorf("rotation clobbered unrelated env: %v", env)
	}
}

// The non-destructive remedy, which did not exist. The only advertised repair
// was --rotate, so the answer to "my settings file holds a dead key" was a
// command that replaced the working one as well.
func TestPlainResyncRepairsTheEnvWithoutMintingAnything(t *testing.T) {
	home, _ := withClaudeSession(t, "good-key", "dead-key")
	v := &fakeVault{valid: map[string]string{"good-key": "claude"}}

	res, err := ResyncClient(v, "akasha", "claude", false)
	if err != nil {
		t.Fatalf("resync: %v", err)
	}
	if res.Rotated {
		t.Error("a plain resync must not rotate")
	}
	if len(v.minted) != 0 {
		t.Errorf("minted %v — repairing an env file needs no new credential", v.minted)
	}
	if got := sessionEnv(t, home)[agentKeyEnv]; got != "good-key" {
		t.Errorf("settings key = %q, want the config's own working key", got)
	}
}

// A healthy config beside a dead session is the shape this failure takes, so a
// check keyed only on the config reports everything fine — which is why it went
// unnoticed on real machines.
func TestCheckAgentsSeesADeadSessionBehindAHealthyConfig(t *testing.T) {
	_, _ = withClaudeSession(t, "good-key", "dead-key")
	v := &fakeVault{valid: map[string]string{"good-key": "claude"}}

	var found bool
	for _, h := range CheckAgents(v) {
		if h.ID != "claude" {
			continue
		}
		found = true
		if h.State != HealthOK {
			t.Errorf("the CONFIG is healthy; State = %v", h.State)
		}
		if !h.NeedsEnvRepair() {
			t.Error("the settings file holds a key the vault rejects and nothing reported it")
		}
		if h.EnvPath == "" {
			t.Error("a warning the user cannot act on: no path named")
		}
	}
	if !found {
		t.Fatal("the claude client was not checked at all")
	}
}

// Ordering. If the environment cannot be written, the previous key must survive.
// A config holding a new key beside an environment holding a revoked one is the
// unrecoverable state, and it is strictly worse than two briefly-valid keys.
func TestAFailedEnvWriteDoesNotRevokeTheWorkingKey(t *testing.T) {
	home, _ := withClaudeSession(t, "old-key", "old-key")
	// Not plain JSON: injectAgentEnv refuses this rather than destroying the
	// comments, which is exactly the write failure worth testing.
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"),
		[]byte("{ // a comment\n \"env\": {} }"), 0600); err != nil {
		t.Fatal(err)
	}
	v := &fakeVault{valid: map[string]string{"old-key": "claude"}}

	if _, err := ResyncClient(v, "akasha", "claude", true); err == nil {
		t.Fatal("a rotation that could not write the session env must report failure")
	}
	if v.revoked["old-key"] {
		t.Error("the previous key was revoked after the env write failed — the " +
			"session is now dead with no way back")
	}
	if _, err := v.VerifyAgentKey("old-key"); err != nil {
		t.Errorf("the key the session still presents must remain valid: %v", err)
	}
}
