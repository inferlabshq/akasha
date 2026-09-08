package setup

import (
	"os"
	"path/filepath"
	"testing"
)

// setupVault satisfies mcpConfigVault. fakeVault in doctor_test.go covers the
// resync interface; this adds the one method setup needs on top of it.
type setupVault struct {
	*fakeVault
	labels []string
}

func (v setupVault) ListLabels(prefix string) ([]string, error) { return v.labels, nil }

// Setup must not retire the old key until the environment holds the new one.
//
// This is the same defect that was fixed in resync, in the path that CREATES
// the situation. Setup wrote the MCP config, revoked the superseded key
// immediately, and only then tried to write the harness env — with that write
// best-effort ("! agent env" and carry on). So a settings file it could not
// write left the old key in the environment and revoked at the same moment: MCP
// tools kept working, every akasha CLI call from that session failed with "agent
// key has been revoked", and the cause was three weeks in the past by the time
// anyone noticed.
//
// Two valid keys for one client is untidy. One revoked key in the file the CLI
// reads is a dead session.
func TestSetupKeepsTheOldKeyWhenTheSessionEnvCannotBeWritten(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	withClaudeConfig(t, `{"mcpServers":{"akasha":{"command":"akasha",`+
		`"args":["mcp","--agent-id","claude"],"env":{"AKASHA_AGENT_KEY":"old-key"}}}}`)

	// A settings file injectAgentEnv refuses: JSONC, which VS Code-family
	// editors tolerate and encoding/json does not.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"),
		[]byte("{ // comment\n \"env\": {} }"), 0600); err != nil {
		t.Fatal(err)
	}

	v := setupVault{fakeVault: &fakeVault{valid: map[string]string{"old-key": "claude"}}}

	configureMCPClients(v, "akasha", []string{"claude"})

	if v.revoked["old-key"] {
		t.Error("setup revoked the superseded key after failing to write the session " +
			"environment — that environment still holds it, so the session is now dead")
	}
	if _, err := v.VerifyAgentKey("old-key"); err != nil {
		t.Errorf("the key the session still presents must remain valid: %v", err)
	}
}

// The other half, so the fix cannot be "never revoke": when both files are
// written, the superseded key must still be retired. Rotation that only ADDS
// leaves a machine carrying one working impersonation credential per setup run.
func TestSetupStillRetiresTheOldKeyWhenBothFilesAreWritten(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	withClaudeConfig(t, `{"mcpServers":{"akasha":{"command":"akasha",`+
		`"args":["mcp","--agent-id","claude"],"env":{"AKASHA_AGENT_KEY":"old-key"}}}}`)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"),
		[]byte(`{"env":{"AKASHA_AGENT_KEY":"old-key"}}`), 0600); err != nil {
		t.Fatal(err)
	}

	v := setupVault{fakeVault: &fakeVault{valid: map[string]string{"old-key": "claude"}}}

	configureMCPClients(v, "akasha", []string{"claude"})

	if !v.revoked["old-key"] {
		t.Error("the superseded key survived a successful setup — a machine set up " +
			"three times would carry three working credentials for one client")
	}
}
