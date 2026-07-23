package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONMCP_FreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")

	if err := writeJSONMCP(path, "mcpServers", map[string]interface{}{
		"command": "/usr/local/bin/akasha",
		"args":    []string{"mcp", "--agent-id", "cursor", "--api-key", "agt_x"},
	}); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)

	servers := cfg["mcpServers"].(map[string]interface{})
	akasha := servers["akasha"].(map[string]interface{})
	if akasha["command"] != "/usr/local/bin/akasha" {
		t.Fatalf("command wrong: %v", akasha["command"])
	}
	args := akasha["args"].([]interface{})
	if args[2] != "cursor" {
		t.Fatalf("agent-id not in args: %v", args)
	}
}

func TestWriteJSONMCP_PreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	// Pre-existing config with another server and unrelated keys.
	os.WriteFile(path, []byte(`{
      "theme": "dark",
      "mcpServers": { "other": { "command": "foo" } }
    }`), 0600)

	if err := writeJSONMCP(path, "mcpServers", map[string]interface{}{
		"command": "akasha", "args": []string{"mcp"},
	}); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)

	if cfg["theme"] != "dark" {
		t.Fatal("unrelated key 'theme' was lost")
	}
	servers := cfg["mcpServers"].(map[string]interface{})
	if _, ok := servers["other"]; !ok {
		t.Fatal("existing server 'other' was lost")
	}
	if _, ok := servers["akasha"]; !ok {
		t.Fatal("akasha server not added")
	}
}

func TestConfigureVSCode_ServersSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	c := mcpClient{id: "vscode", label: "VS Code (Copilot)", dir: dir, cfgPath: path, format: "json", jsonKey: "servers"}

	if err := c.configure("/usr/local/bin/akasha", "agt_vs"); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)

	// VS Code uses top-level "servers", NOT "mcpServers".
	if _, ok := cfg["mcpServers"]; ok {
		t.Fatal("VS Code config must not use mcpServers key")
	}
	servers, ok := cfg["servers"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing servers key: %s", data)
	}
	akasha, ok := servers["akasha"].(map[string]interface{})
	if !ok {
		t.Fatal("akasha server not written")
	}
	if akasha["type"] != "stdio" {
		t.Errorf("VS Code server needs type=stdio, got %v", akasha["type"])
	}
	if akasha["command"] != "/usr/local/bin/akasha" {
		t.Errorf("command wrong: %v", akasha["command"])
	}

	// The doctor must read it back through the "servers" key.
	args, found := c.readAkashaArgs()
	if !found {
		t.Fatal("readAkashaArgs failed for VS Code")
	}
	id, key, _ := agentIDAndKey(args)
	if id != "vscode" || key != "agt_vs" {
		t.Errorf("got id=%q key=%q", id, key)
	}
}

func TestWriteTOMLMCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte("model = \"gpt-5\"\n"), 0600)

	if err := writeTOMLMCP(path, "akasha",
		[]string{"mcp", "--agent-id", "codex", "--api-key", "agt_y"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, `model = "gpt-5"`) {
		t.Fatal("existing TOML content lost")
	}
	if !strings.Contains(s, "[mcp_servers.akasha]") {
		t.Fatal("akasha block not written")
	}
	if !strings.Contains(s, `"--agent-id", "codex"`) {
		t.Fatalf("args not in TOML:\n%s", s)
	}
}

func TestWriteTOMLMCP_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	args := []string{"mcp", "--agent-id", "codex"}

	writeTOMLMCP(path, "akasha", args)
	writeTOMLMCP(path, "akasha", args) // second call should be a no-op

	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "[mcp_servers.akasha]") != 1 {
		t.Fatal("akasha block written twice")
	}
}

func TestClientInstalledDetection(t *testing.T) {
	// A client whose dir exists should be detected.
	dir := t.TempDir()
	c := mcpClient{id: "x", dir: dir, cfgPath: filepath.Join(dir, "c.json"), format: "json"}
	if !c.installed() {
		t.Fatal("expected installed=true when dir exists")
	}

	missing := mcpClient{id: "y", dir: "/nonexistent/zzz", cfgPath: "/nonexistent/zzz/c.json"}
	if missing.installed() {
		t.Fatal("expected installed=false for missing paths")
	}
}

func TestExpandHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	if got := expand("~/.cursor/mcp.json"); got != filepath.Join(home, ".cursor/mcp.json") {
		t.Fatalf("expand wrong: %s", got)
	}
	if got := expand("/abs/path"); got != "/abs/path" {
		t.Fatalf("absolute path should be unchanged: %s", got)
	}
}
