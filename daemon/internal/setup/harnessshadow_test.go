package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJSON(t *testing.T, p string, v interface{}) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, p string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const fakeKey = "agt_claude_DUMMY_NOT_A_REAL_KEY"

// The run's Claude Code config keeps the user's settings and MCP servers and
// loses every variable setup injected — the key above all.
func TestShadowClaudeConfigScrubsAkashaAndKeepsTheRest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	cfg := filepath.Join(home, ".claude")
	os.MkdirAll(filepath.Join(cfg, "projects"), 0o700)
	os.WriteFile(filepath.Join(cfg, "history.jsonl"), []byte("{}\n"), 0o600)
	agentsDir := filepath.Join(home, ".akasha", "agents", "claude")
	writeJSON(t, filepath.Join(cfg, "settings.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{}},
		"env": map[string]interface{}{
			"AKASHA_AGENT_KEY": fakeKey,
			"AKASHA_AGENT_ID":  "claude",
			"AWS_CONFIG_FILE":  filepath.Join(agentsDir, "aws.config"),
			"MY_OWN_VAR":       "kept",
		},
	})
	writeJSON(t, filepath.Join(home, ".claude.json"), map[string]interface{}{
		"oauthAccount": map[string]interface{}{"displayName": "T"},
		"mcpServers": map[string]interface{}{
			"akasha": map[string]interface{}{"command": "akasha", "env": map[string]interface{}{"AKASHA_AGENT_KEY": fakeKey}},
			"other":  map[string]interface{}{"command": "x", "env": map[string]interface{}{"TOKEN_FOR_OTHER": "kept"}},
		},
		"projects": map[string]interface{}{
			"/p": map[string]interface{}{"mcpServers": map[string]interface{}{
				"akasha": map[string]interface{}{"env": map[string]interface{}{"AKASHA_AGENT_KEY": fakeKey}},
			}},
		},
	})
	origSettings, _ := os.ReadFile(filepath.Join(cfg, "settings.json"))

	dir, err := ShadowClaudeConfig(t.TempDir())
	if err != nil || dir == "" {
		t.Fatalf("ShadowClaudeConfig = %q, %v", dir, err)
	}
	for _, f := range []string{"settings.json", ".claude.json"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
		if strings.Contains(string(b), fakeKey) || strings.Contains(string(b), "AKASHA_") {
			t.Fatalf("%s still carries akasha's variables:\n%s", f, b)
		}
	}
	s := readJSON(t, filepath.Join(dir, "settings.json"))
	if env, _ := s["env"].(map[string]interface{}); env["MY_OWN_VAR"] != "kept" || env["AWS_CONFIG_FILE"] != nil {
		t.Fatalf("settings env should keep the user's var and drop akasha-agent paths: %v", s["env"])
	}
	if s["hooks"] == nil {
		t.Fatal("the user's hooks were dropped")
	}
	g := readJSON(t, filepath.Join(dir, ".claude.json"))
	other := g["mcpServers"].(map[string]interface{})["other"].(map[string]interface{})["env"].(map[string]interface{})
	if other["TOKEN_FOR_OTHER"] != "kept" || g["oauthAccount"] == nil {
		t.Fatalf("the user's own config was not preserved: %v", g)
	}
	for _, name := range []string{"history.jsonl", "projects"} {
		if fi, err := os.Lstat(filepath.Join(dir, name)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s should be a live symlink into the real config: %v", name, err)
		}
	}
	if now, _ := os.ReadFile(filepath.Join(cfg, "settings.json")); string(now) != string(origSettings) {
		t.Fatal("the original settings.json was modified")
	}
}

func TestShadowClaudeConfigWithoutClaude(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if dir, err := ShadowClaudeConfig(t.TempDir()); dir != "" || err != nil {
		t.Fatalf("no Claude config should mean no shadow, got %q, %v", dir, err)
	}
}

// A file that is not plain JSON is not copied at all: the harness sees its
// defaults for it, never a copy that might still carry a key.
func TestShadowClaudeConfigSkipsUnparseable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("// comment\n{\"env\":{\"AKASHA_AGENT_KEY\":\""+fakeKey+"\"}}"), 0o600)
	dir, err := ShadowClaudeConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); !os.IsNotExist(err) {
		t.Fatal("an unparseable settings.json was copied")
	}
}
