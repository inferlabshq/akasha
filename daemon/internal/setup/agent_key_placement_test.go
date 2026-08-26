package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An agent key on the command line is public. `ps` and /proc/<pid>/cmdline are
// readable by every process on the machine — other users included, and the
// agent whose Bash tool runs `ps` among them — so a key in args could be lifted
// and used to act under another client's identity, which defeats per-agent
// attribution in the audit log and makes `akasha agent revoke` revoke the wrong
// thing. The key belongs in the env block; the args must carry only the
// identity name.
func TestConfigureKeepsTheKeyOutOfArgv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	c := mcpClient{id: "cursor", label: "Cursor", dir: dir, cfgPath: path, format: "json"}

	if err := c.configure("/usr/local/bin/akasha", "agt_supersecret"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)

	var cfg map[string]interface{}
	json.Unmarshal(raw, &cfg)
	akasha := cfg["mcpServers"].(map[string]interface{})["akasha"].(map[string]interface{})

	argsJSON, _ := json.Marshal(akasha["args"])
	if strings.Contains(string(argsJSON), "agt_supersecret") {
		t.Errorf("the agent key is in argv: %s", argsJSON)
	}
	if strings.Contains(string(argsJSON), "--api-key") {
		t.Errorf("--api-key must no longer be written: %s", argsJSON)
	}
	env, ok := akasha["env"].(map[string]interface{})
	if !ok || env[agentKeyEnv] != "agt_supersecret" {
		t.Fatalf("the key must travel in the env block, got env=%v", akasha["env"])
	}

	// And the doctor has to be able to read it back, or `akasha status` reports
	// every client as unconfigured and `agent resync` mints a key nobody needs.
	args, envRead, found := c.readAkashaEntry()
	if !found {
		t.Fatal("readAkashaEntry did not find the entry it just wrote")
	}
	if got := configuredKey(args, envRead); got != "agt_supersecret" {
		t.Errorf("configuredKey = %q, want agt_supersecret", got)
	}
	if id, _, _ := agentIDAndKey(args); id != "cursor" {
		t.Errorf("agent-id must stay in args (it is not a secret), got %q", id)
	}
}

// The same, for the one client whose config is TOML.
func TestConfigureTOMLKeepsTheKeyOutOfArgv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte("model = \"gpt-5\"\n"), 0600)
	c := mcpClient{id: "codex", label: "Codex", dir: dir, cfgPath: path, format: "toml"}

	if err := c.configure("akasha", "agt_codexkey"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	s := string(raw)
	if !strings.Contains(s, `model = "gpt-5"`) {
		t.Fatal("existing TOML content lost")
	}
	argsLine := ""
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "args") {
			argsLine = line
		}
	}
	if strings.Contains(argsLine, "agt_codexkey") {
		t.Errorf("the agent key is in argv: %s", argsLine)
	}
	args, env, found := c.readAkashaEntry()
	if !found {
		t.Fatal("readAkashaEntry did not find the TOML entry it just wrote")
	}
	if got := configuredKey(args, env); got != "agt_codexkey" {
		t.Errorf("configuredKey = %q, want agt_codexkey\n%s", got, s)
	}
}

// A machine set up before the key moved still has it in args. That config must
// keep working — the doctor has to read the legacy form, or `akasha status`
// declares a perfectly good client desynced and resync rotates a key that was
// never stale.
func TestConfiguredKeyStillReadsTheLegacyArgvForm(t *testing.T) {
	args := []string{"mcp", "--agent-id", "claude", "--api-key", "agt_old"}
	if got := configuredKey(args, nil); got != "agt_old" {
		t.Errorf("legacy --api-key config: configuredKey = %q, want agt_old", got)
	}
	// And the env wins when both are present, so a rewrite is what takes effect.
	if got := configuredKey(args, map[string]string{agentKeyEnv: "agt_new"}); got != "agt_new" {
		t.Errorf("env must take precedence over a leftover --api-key, got %q", got)
	}
}

// Rewriting a TOML config has to REPLACE the akasha block. It used to return
// early whenever one existed, so `setup` and `agent resync --rotate` minted a
// new key, "wrote" it, then revoked the old one — leaving Codex holding a
// credential the daemon had just retired. It is also what migrates an existing
// install off the argv form.
func TestTOMLRewriteReplacesTheBlockInsteadOfSkippingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	c := mcpClient{id: "codex", label: "Codex", dir: dir, cfgPath: path, format: "toml"}

	if err := c.configure("akasha", "agt_first"); err != nil {
		t.Fatal(err)
	}
	if err := c.configure("akasha", "agt_second"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), "[mcp_servers.akasha]") != 1 {
		t.Fatalf("expected exactly one akasha block:\n%s", raw)
	}
	if strings.Contains(string(raw), "agt_first") {
		t.Errorf("the superseded key is still in the config — it has been revoked by now:\n%s", raw)
	}
	args, env, _ := c.readAkashaEntry()
	if got := configuredKey(args, env); got != "agt_second" {
		t.Errorf("configuredKey = %q, want agt_second\n%s", got, raw)
	}
}

// The user-visible half of the move: `akasha status` reads the config through
// CheckAgents, so a key it cannot find is reported as HealthNoKey and
// `akasha agent resync` mints a replacement for a client that was never broken.
// Both the current form (env) and the legacy one (args) must verify.
func TestCheckAgentsFindsTheKeyInEitherPlace(t *testing.T) {
	fv := &fakeVault{valid: map[string]string{"agt_good": "claude"}}

	for _, tc := range []struct {
		name string
		file string
		want HealthState
	}{
		{"key in the env block", `{"mcpServers":{"akasha":{"command":"akasha",` +
			`"args":["mcp","--agent-id","claude"],"env":{"AKASHA_AGENT_KEY":"agt_good"}}}}`, HealthOK},
		{"legacy key in args", `{"mcpServers":{"akasha":{"command":"akasha",` +
			`"args":["mcp","--agent-id","claude","--api-key","agt_good"]}}}`, HealthOK},
		{"genuinely no key", `{"mcpServers":{"akasha":{"command":"akasha",` +
			`"args":["mcp","--agent-id","claude"],"env":{}}}}`, HealthNoKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withClaudeConfig(t, tc.file)
			if got := stateFor(t, CheckAgents(fv), "claude"); got != tc.want {
				t.Errorf("state = %v, want %v", got, tc.want)
			}
		})
	}
}
