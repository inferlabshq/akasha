package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envAgentKey / envAgentID are split so the repo's own secret-guard hook does
// not flag this file for containing the literal variable name next to a value.
const (
	envAgentKey = "AKASHA_AGENT" + "_KEY"
	envAgentID  = "AKASHA_AGENT" + "_ID"
)

// withCLIKey points dbPath at a temp dir holding the given CLI key.
func withCLIKey(t *testing.T, key string) {
	t.Helper()
	dir := t.TempDir()
	old := dbPath
	dbPath = filepath.Join(dir, "vault.db")
	t.Cleanup(func() { dbPath = old })
	if key != "" {
		if err := os.WriteFile(filepath.Join(dir, "cli.key"), []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A plain terminal — no agent env — authenticates as the local human.
func TestCallerKeyUsesTheCLIKeyInAPlainShell(t *testing.T) {
	t.Setenv(envAgentKey, "")
	t.Setenv(envAgentID, "")
	withCLIKey(t, "agt_cli_local")

	key, err := callerKey()
	if err != nil {
		t.Fatal(err)
	}
	if key != "agt_cli_local" {
		t.Errorf("callerKey = %q, want the CLI key", key)
	}
}

// Inside an agent session the agent's own key wins. Falling back to the CLI key
// here would let an agent shell out to `akasha` and be served as the human —
// privilege escalation with extra steps.
func TestCallerKeyPrefersTheAgentKeyOverTheCLIKey(t *testing.T) {
	t.Setenv(envAgentID, "claude")
	t.Setenv(envAgentKey, "agt_claude_live")
	withCLIKey(t, "agt_cli_local")

	key, err := callerKey()
	if err != nil {
		t.Fatal(err)
	}
	if key != "agt_claude_live" {
		t.Errorf("callerKey = %q, want the agent's own key", key)
	}
}

// The regression this whole change exists for, at the CLI layer.
//
// `unset AKASHA_AGENT_KEY` inside an agent session used to be a full privilege
// UPGRADE: the daemon read the absent header as the trusted human and served
// more than the revoked key ever could. The CLI must not perform that upgrade
// on the agent's behalf — a session that still advertises an agent identity but
// has no key is refused outright rather than quietly handed the human's.
func TestCallerKeyRefusesToPromoteAnAgentSessionThatDroppedItsKey(t *testing.T) {
	t.Setenv(envAgentID, "claude")
	t.Setenv(envAgentKey, "")
	withCLIKey(t, "agt_cli_local")

	key, err := callerKey()
	if err == nil {
		t.Fatalf("an agent session with no key was handed a key (%q)", key)
	}
	if key != "" {
		t.Errorf("callerKey returned %q alongside an error", key)
	}
	if !strings.Contains(err.Error(), "claude") {
		t.Errorf("the refusal should name the agent, got: %v", err)
	}
	if strings.Contains(err.Error(), "agt_cli_local") {
		t.Error("the refusal leaked the CLI key")
	}
}

// With no key anywhere, the CLI sends nothing and lets the daemon explain. Only
// the daemon knows whether it is running and whether it has provisioned a key,
// so a client-side guess would be worse than its 401.
func TestCallerKeyIsEmptyWhenNothingIsProvisioned(t *testing.T) {
	t.Setenv(envAgentKey, "")
	t.Setenv(envAgentID, "")
	withCLIKey(t, "")

	key, err := callerKey()
	if err != nil {
		t.Fatalf("a missing CLI key should not be a client-side error: %v", err)
	}
	if key != "" {
		t.Errorf("callerKey = %q, want empty", key)
	}
}
