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

// GUARANTEE: the mirror of TestRemoveJSONMCPRefusesJSONC. VS Code's mcp.json is
// canonically JSONC, so a tolerant unmarshal here would rewrite the file from
// whatever half-parse survived — silently deleting the user's comments and any
// server we could not read.
func TestWriteJSONMCPRefusesJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	orig := "// user comment\n{\"servers\": {\"other\": {\"command\": \"foo\"}}}\n"
	os.WriteFile(path, []byte(orig), 0600)

	err := writeJSONMCP(path, "servers", map[string]interface{}{
		"command": "/usr/local/bin/akasha",
		"args":    []string{"mcp", "--agent-id", "vscode"},
		"type":    "stdio",
	})
	if err == nil {
		t.Fatal("expected refusal on JSONC config")
	}
	// The precious file must be untouched.
	data, _ := os.ReadFile(path)
	if string(data) != orig {
		t.Fatalf("JSONC config file was modified:\n%s", data)
	}
	// The error must name the file, the key, and the entry to add by hand.
	for _, want := range []string{shorten(path), `"servers"`, `"akasha"`, "/usr/local/bin/akasha", "--agent-id"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should carry manual instructions (%q): %v", want, err)
		}
	}
}

// configure must propagate the refusal rather than reporting a write that did
// not happen.
func TestConfigureRefusesJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	orig := "// user comment\n{\"servers\": {}}\n"
	os.WriteFile(path, []byte(orig), 0600)

	c := mcpClient{id: "vscode", label: "VS Code (Copilot)", dir: dir, cfgPath: path, format: "json", jsonKey: "servers"}
	if err := c.configure("/usr/local/bin/akasha", "agt_vs"); err == nil {
		t.Fatal("configure should surface the refusal")
	}
	data, _ := os.ReadFile(path)
	if string(data) != orig {
		t.Fatalf("JSONC config file was modified:\n%s", data)
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
	args, env, found := c.readAkashaEntry()
	if !found {
		t.Fatal("readAkashaEntry failed for VS Code")
	}
	id, _, _ := agentIDAndKey(args)
	if key := configuredKey(args, env); id != "vscode" || key != "agt_vs" {
		t.Errorf("got id=%q key=%q", id, key)
	}
}

func TestWriteTOMLMCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte("model = \"gpt-5\"\n"), 0600)

	if err := writeTOMLMCP(path, "akasha",
		[]string{"mcp", "--agent-id", "codex"},
		map[string]string{"AKASHA_AGENT_KEY": "agt_y"}); err != nil {
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

	writeTOMLMCP(path, "akasha", args, nil)
	writeTOMLMCP(path, "akasha", args, nil) // second call replaces, never appends

	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "[mcp_servers.akasha]") != 1 {
		t.Fatal("akasha block written twice")
	}
}

// The key moved out of argv and into the config file's env block, which is only
// a move if the file is not world-readable. os.WriteFile applies its mode when
// it CREATES the file and these files usually exist first — the client wrote
// them, at 0644 under a default umask — so `akasha setup` was writing a live
// agent key into a file every uid on the box could read. A home directory is
// usually 0700 and hides it in practice, but the threat model's claim is that
// the key is at the same-uid ceiling, and "usually" is not that claim.
func TestConfigsHoldingTheKeyAreNotLeftWorldReadable(t *testing.T) {
	dir := t.TempDir()
	json1 := filepath.Join(dir, "mcp.json")
	toml1 := filepath.Join(dir, "config.toml")

	// Both pre-created by the client, at the mode a default umask gives.
	for _, p := range []string{json1, toml1} {
		if err := os.WriteFile(p, []byte("{}\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0644); err != nil { // WriteFile does not re-apply it either
			t.Fatal(err)
		}
	}

	if err := writeJSONMCP(json1, "mcpServers", map[string]interface{}{
		"command": "akasha", "env": map[string]string{"AKASHA_AGENT_KEY": "agt_x"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeTOMLMCP(toml1, "akasha", []string{"mcp", "--agent-id", "codex"},
		map[string]string{"AKASHA_AGENT_KEY": "agt_y"}); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{json1, toml1} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0600 {
			t.Errorf("%s holds a live agent key at mode %#o, want 0600", filepath.Base(p), mode)
		}
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
