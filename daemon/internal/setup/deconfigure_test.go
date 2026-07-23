package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// removeJSONMCP must delete only the "akasha" server and leave every other
// server (and unrelated top-level keys) exactly as they were.
func TestRemoveJSONMCP_PreservesOtherServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")

	// configure writes akasha alongside a pre-existing server + unrelated key.
	seed := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"other": map[string]interface{}{"command": "/bin/other"},
		},
		"editor.fontSize": 14,
	}
	out, _ := json.MarshalIndent(seed, "", "  ")
	os.WriteFile(path, out, 0600)
	if err := writeJSONMCP(path, "mcpServers",
		map[string]interface{}{"command": "akasha", "args": []string{"mcp"}}); err != nil {
		t.Fatal(err)
	}

	changed, err := removeJSONMCP(path, "mcpServers")
	if err != nil || !changed {
		t.Fatalf("removeJSONMCP: changed=%v err=%v", changed, err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)

	servers := cfg["mcpServers"].(map[string]interface{})
	if _, ok := servers["akasha"]; ok {
		t.Fatal("akasha server still present after removal")
	}
	if _, ok := servers["other"]; !ok {
		t.Fatal("unrelated server 'other' was wrongly removed")
	}
	if cfg["editor.fontSize"] == nil {
		t.Fatal("unrelated top-level key was dropped")
	}
}

// When akasha was the only server, removal drops the now-empty container key so
// the file is restored to its pre-setup shape.
func TestRemoveJSONMCP_DropsEmptyContainer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := writeJSONMCP(path, "servers",
		map[string]interface{}{"command": "akasha", "type": "stdio"}); err != nil {
		t.Fatal(err)
	}
	if _, err := removeJSONMCP(path, "servers"); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)
	if _, ok := cfg["servers"]; ok {
		t.Fatal("empty 'servers' container should have been removed")
	}
}

// removeJSONMCP is a no-op (changed=false) when there's no akasha entry.
func TestRemoveJSONMCP_NoEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	os.WriteFile(path, []byte(`{"mcpServers":{"other":{"command":"x"}}}`), 0600)
	changed, err := removeJSONMCP(path, "mcpServers")
	if err != nil || changed {
		t.Fatalf("expected no change; got changed=%v err=%v", changed, err)
	}
}

// removeTOMLMCP strips the akasha block but keeps surrounding tables intact.
func TestRemoveTOMLMCP_PreservesOtherTables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := writeTOMLMCP(path, "akasha", []string{"mcp", "--agent-id", "codex"}); err != nil {
		t.Fatal(err)
	}
	// Append an unrelated table after akasha's block.
	data, _ := os.ReadFile(path)
	os.WriteFile(path, append(data, []byte("\n[other_table]\nkey = \"val\"\n")...), 0600)

	changed, err := removeTOMLMCP(path)
	if err != nil || !changed {
		t.Fatalf("removeTOMLMCP: changed=%v err=%v", changed, err)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	if strings.Contains(s, "mcp_servers.akasha") {
		t.Fatalf("akasha block survived:\n%s", s)
	}
	if !strings.Contains(s, "[other_table]") || !strings.Contains(s, `key = "val"`) {
		t.Fatalf("unrelated table was damaged:\n%s", s)
	}
}

// removeAgentEnv deletes AKASHA_* and agent-dir-pointing vars, but never a
// user's own variable that happens to share a name.
func TestRemoveAgentEnv_ValueAware(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	agentDir := filepath.Join(agentsBase(), "claude") // ~/.akasha/agents/claude

	seed := map[string]interface{}{
		"env": map[string]interface{}{
			"AKASHA_AGENT_ID":             "claude",
			"AKASHA_AGENT_KEY":            "agt_secret",
			"AWS_CONFIG_FILE":             filepath.Join(agentDir, "aws.config"), // akasha-owned
			"AWS_SHARED_CREDENTIALS_FILE": "/home/me/.aws/creds",                 // user's own
			"EDITOR":                      "vim",                                 // unrelated
		},
	}
	out, _ := json.MarshalIndent(seed, "", "  ")
	os.WriteFile(path, out, 0600)

	target := &envTarget{path: path, keys: []string{"env"}}
	changed, err := removeAgentEnv(target)
	if err != nil || !changed {
		t.Fatalf("removeAgentEnv: changed=%v err=%v", changed, err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)
	env := cfg["env"].(map[string]interface{})

	for _, gone := range []string{"AKASHA_AGENT_ID", "AKASHA_AGENT_KEY", "AWS_CONFIG_FILE"} {
		if _, ok := env[gone]; ok {
			t.Fatalf("%s should have been removed", gone)
		}
	}
	if env["AWS_SHARED_CREDENTIALS_FILE"] != "/home/me/.aws/creds" {
		t.Fatal("user's own AWS_SHARED_CREDENTIALS_FILE was wrongly removed")
	}
	if env["EDITOR"] != "vim" {
		t.Fatal("unrelated EDITOR var was wrongly removed")
	}
}

// When akasha owned every var in the map, the now-empty env key is dropped.
func TestRemoveAgentEnv_DropsEmptyMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	os.WriteFile(path, []byte(`{"env":{"AKASHA_AGENT_ID":"claude"},"theme":"dark"}`), 0600)

	if _, err := removeAgentEnv(&envTarget{path: path, keys: []string{"env"}}); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)
	if _, ok := cfg["env"]; ok {
		t.Fatal("empty env map should have been removed")
	}
	if cfg["theme"] != "dark" {
		t.Fatal("unrelated key 'theme' was dropped")
	}
}
