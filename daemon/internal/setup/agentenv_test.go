package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// trustAll approves every provider's ownership, for tests that exercise the
// generation path rather than the trust gate.
func trustAll(*template.Template) bool { return true }

func TestWriteAgentDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	env, _, err := writeAgentDir("claude", "/usr/local/bin/akasha", trustAll, func(provider string) []string {
		if provider == "aws" {
			return []string{"default", "pk-website"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	agentDir := filepath.Join(home, ".akasha", "agents", "claude")

	// Env from the AWS template's agent block, fully resolved.
	if env["AWS_CONFIG_FILE"] != filepath.Join(agentDir, "aws.config") {
		t.Fatalf("AWS_CONFIG_FILE = %q", env["AWS_CONFIG_FILE"])
	}
	if env["AKASHA_AGENT_ID"] != "claude" {
		t.Fatalf("AKASHA_AGENT_ID = %q", env["AKASHA_AGENT_ID"])
	}

	// Config stub: one credential_process block per vaulted instance.
	data, err := os.ReadFile(filepath.Join(agentDir, "aws.config"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(data)
	for _, want := range []string{
		"[profile default]",
		"[profile pk-website]",
		"credential_process = /usr/local/bin/akasha helper aws --instance default",
		"credential_process = /usr/local/bin/akasha helper aws --instance pk-website",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("aws.config missing %q:\n%s", want, cfg)
		}
	}
}

// TestWriteAgentDirGitHubPreamble exercises the real builtin github.yaml agent
// block: owning GIT_CONFIG_GLOBAL, emitting the ~/.gitconfig include preamble
// once at the top, and host-scoping a credential helper that routes through the
// daemon. This is the second provider (after AWS) to get mandatory env
// ownership, and the first to use a preamble.
func TestWriteAgentDirGitHubPreamble(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	env, _, err := writeAgentDir("claude", "/usr/local/bin/akasha", trustAll, func(provider string) []string {
		if provider == "github" {
			return []string{"default"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	agentDir := filepath.Join(home, ".akasha", "agents", "claude")
	if env["GIT_CONFIG_GLOBAL"] != filepath.Join(agentDir, "github.gitconfig") {
		t.Fatalf("GIT_CONFIG_GLOBAL = %q", env["GIT_CONFIG_GLOBAL"])
	}

	data, err := os.ReadFile(filepath.Join(agentDir, "github.gitconfig"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(data)
	for _, want := range []string{
		"[include]",
		"path = ~/.gitconfig",
		`[credential "https://github.com"]`,
		"helper = !/usr/local/bin/akasha helper github --instance default",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("github.gitconfig missing %q:\n%s", want, cfg)
		}
	}

	// The preamble (user-config include) must come BEFORE the credential stub,
	// so the user's identity loads first and Akasha's helper overrides only the
	// credential wiring.
	if strings.Index(cfg, "[include]") > strings.Index(cfg, "[credential") {
		t.Fatalf("preamble must precede per-instance stub:\n%s", cfg)
	}

	// The empty `helper =` reset must precede our helper line, so an inherited
	// keychain helper cannot answer for github.com instead of the daemon.
	resetIdx := strings.Index(cfg, "helper =\n")
	if resetIdx == -1 || resetIdx > strings.Index(cfg, "helper = !") {
		t.Fatalf("expected a `helper =` reset before the daemon helper:\n%s", cfg)
	}
}

// TestWriteAgentDirTrustGate is the security property: an untrusted provider's
// ownership block is NOT applied — no env, no config file — and it is reported
// in skipped so the caller can tell the user to approve it.
func TestWriteAgentDirTrustGate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Trust github, deny aws.
	trusted := func(tp *template.Template) bool { return tp.Name == "github" }
	env, skipped, err := writeAgentDir("claude", "akasha", trusted, func(provider string) []string {
		return []string{"default"} // both providers have a vaulted instance
	})
	if err != nil {
		t.Fatal(err)
	}

	// aws was denied: its env var must be absent and its config file unwritten.
	if _, ok := env["AWS_CONFIG_FILE"]; ok {
		t.Fatalf("denied provider aws leaked env: %v", env)
	}
	agentDir := filepath.Join(home, ".akasha", "agents", "claude")
	if _, err := os.Stat(filepath.Join(agentDir, "aws.config")); !os.IsNotExist(err) {
		t.Fatal("denied provider aws must not write a config stub")
	}
	// github was trusted: its env var is present.
	if env["GIT_CONFIG_GLOBAL"] == "" {
		t.Fatalf("trusted provider github was not applied: %v", env)
	}
	// aws (and any other ownership provider) must be reported as skipped.
	if !containsStr(skipped, "aws") {
		t.Fatalf("aws should be reported skipped, got %v", skipped)
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestWriteAgentDirNoInstances(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, _, err := writeAgentDir("claude", "akasha", trustAll, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// No vaulted instances → no stub file, but env still points at the
	// (future) config so later discovers take effect on restart.
	if _, err := os.Stat(filepath.Join(home, ".akasha", "agents", "claude", "aws.config")); !os.IsNotExist(err) {
		t.Fatal("config stub should not exist without instances")
	}
}

func TestInjectAgentEnvMergesAndPreserves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	os.WriteFile(path, []byte(`{
  "model": "opus",
  "env": {"EXISTING": "keep"}
}`), 0600)

	target := &envTarget{path: path, keys: []string{"env"}}
	if err := injectAgentEnv(target, map[string]string{"AWS_CONFIG_FILE": "/x/aws.config"}); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["model"] != "opus" {
		t.Fatal("unrelated settings clobbered")
	}
	env := cfg["env"].(map[string]interface{})
	if env["EXISTING"] != "keep" || env["AWS_CONFIG_FILE"] != "/x/aws.config" {
		t.Fatalf("env merge wrong: %v", env)
	}
}

func TestInjectAgentEnvCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "settings.json")

	target := &envTarget{path: path, keys: []string{"terminal.integrated.env.osx"}}
	if err := injectAgentEnv(target, map[string]string{"K": "v"}); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)
	envMap := cfg["terminal.integrated.env.osx"].(map[string]interface{})
	if envMap["K"] != "v" {
		t.Fatalf("cfg = %v", cfg)
	}
}

func TestInjectAgentEnvRefusesJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	orig := "// user comment\n{\"a\": 1}\n"
	os.WriteFile(path, []byte(orig), 0600)

	target := &envTarget{path: path, keys: []string{"env"}}
	err := injectAgentEnv(target, map[string]string{"K": "v"})
	if err == nil {
		t.Fatal("expected refusal on JSONC settings")
	}
	// The precious file must be untouched.
	data, _ := os.ReadFile(path)
	if string(data) != orig {
		t.Fatal("JSONC settings file was modified")
	}
	// The error must tell the user what to add by hand.
	if !strings.Contains(err.Error(), "K=v") {
		t.Fatalf("error should carry manual instructions: %v", err)
	}
}

func TestEnvTargetFor(t *testing.T) {
	for _, c := range mcpClients {
		target := c.envTargetFor()
		switch c.id {
		case "claude":
			if target == nil || target.keys[0] != "env" || !strings.Contains(target.path, ".claude/settings.json") {
				t.Fatalf("claude target wrong: %+v", target)
			}
		case "vscode", "cursor":
			if target == nil || !strings.Contains(target.keys[0], "terminal.integrated.env") {
				t.Fatalf("%s target wrong: %+v", c.id, target)
			}
			if !strings.HasSuffix(target.path, "/settings.json") || strings.Contains(target.path, "mcp.json") {
				t.Fatalf("%s settings path wrong: %q", c.id, target.path)
			}
		case "windsurf", "codex":
			if target != nil {
				t.Fatalf("%s should have no env target yet", c.id)
			}
		}
	}
}
