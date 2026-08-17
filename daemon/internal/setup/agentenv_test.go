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
// Discovery keys the git provider by HOST (~/.git-credentials is a list of
// https://user:token@host lines), so it produces labels like git:github.com. The
// shipped git.yaml previously had no agent block, so those labels had no broker
// wired to them and GIT_CONFIG_GLOBAL was exported pointing at a file nothing
// wrote — which made git ignore the user's real ~/.gitconfig inside agent
// sessions. This renders against the REAL bundled template.
func TestWriteAgentDirWiresDiscoveredGitHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	env, _, err := writeAgentDir("claude", "/usr/local/bin/akasha", trustAll, func(provider string) []string {
		if provider == "git" {
			return []string{"github.com", "gitlab.example.org"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	path := env["GIT_CONFIG_GLOBAL"]
	if path == "" {
		t.Fatal("GIT_CONFIG_GLOBAL was not exported")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("GIT_CONFIG_GLOBAL points at a file that does not exist (%s): %v", path, err)
	}
	cfg := string(data)
	for _, want := range []string{
		"path = ~/.gitconfig",
		`[credential "https://github.com"]`,
		`[credential "https://gitlab.example.org"]`,
		"helper = !/usr/local/bin/akasha helper git --instance github.com",
		"helper = !/usr/local/bin/akasha helper git --instance gitlab.example.org",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("gitconfig missing %q:\n%s", want, cfg)
		}
	}
}

// A GITHUB_TOKEN in a shell rc names no host. Those rules used to live in
// git.yaml, whose instance for them was the literal "default", so ownership
// scoped a credential helper to a host called "default" — a section git will
// never consult, leaving the token vaulted but unreachable. They now live in
// github.yaml, where the host is known, so the same "default" instance lands on
// github.com. Renders against the REAL bundled templates.
func TestWriteAgentDirWiresHostlessTokensToTheirService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	env, _, err := writeAgentDir("claude", "/usr/local/bin/akasha", trustAll, func(provider string) []string {
		switch provider {
		case "github", "gitlab":
			return []string{"default"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(env["GIT_CONFIG_GLOBAL"])
	if err != nil {
		t.Fatalf("GIT_CONFIG_GLOBAL points at a file that does not exist: %v", err)
	}
	cfg := string(data)
	for _, want := range []string{
		`[credential "https://github.com"]`,
		`[credential "https://gitlab.com"]`,
		"helper = !/usr/local/bin/akasha helper github --instance default",
		"helper = !/usr/local/bin/akasha helper gitlab --instance default",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("gitconfig missing %q:\n%s", want, cfg)
		}
	}
	// The symptom that motivated the move: a helper scoped to a host that is
	// really an "I could not tell" sentinel.
	if strings.Contains(cfg, `https://default`) {
		t.Fatalf("a credential section was scoped to the sentinel host:\n%s", cfg)
	}
}

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
	if filepath.Dir(env["GIT_CONFIG_GLOBAL"]) != agentDir {
		t.Fatalf("GIT_CONFIG_GLOBAL = %q", env["GIT_CONFIG_GLOBAL"])
	}

	data, err := os.ReadFile(env["GIT_CONFIG_GLOBAL"])
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

// GUARANTEE: setting up an agent with nothing vaulted yet is inert for AWS but
// must NOT leave GIT_CONFIG_GLOBAL dangling. Git reads that variable as a
// REPLACEMENT for ~/.gitconfig, so a path with no file behind it silently
// strips user.name/user.email from every session — commits then fail with
// "Author identity unknown" or land misattributed.
func TestWriteAgentDirNoInstances(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	env, _, err := writeAgentDir("claude", "akasha", trustAll, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// AWS's credential_process stub has nothing to say without instances, and a
	// missing AWS config file just means "no profiles" — harmless. Env still
	// points at the future config so a later discover takes effect on restart.
	if _, err := os.Stat(filepath.Join(home, ".akasha", "agents", "claude", "aws.config")); !os.IsNotExist(err) {
		t.Fatal("config stub should not exist without instances")
	}

	gitconfig := env["GIT_CONFIG_GLOBAL"]
	if gitconfig == "" {
		t.Fatal("GIT_CONFIG_GLOBAL should still be exported with nothing vaulted")
	}
	data, err := os.ReadFile(gitconfig)
	if err != nil {
		t.Fatalf("GIT_CONFIG_GLOBAL is exported but no file exists — the user's git identity is gone: %v", err)
	}
	for _, want := range []string{"[include]", "path = ~/.gitconfig"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("zero-instance gitconfig missing %q:\n%s", want, data)
		}
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

// GUARANTEE: the inverse of injectAgentEnv fails LOUDLY on the same file it
// refuses to write. VS Code's settings.json is canonically JSONC, so this is
// the default case there — and returning "nothing to remove" would let
// `akasha uninstall --purge` delete the agent dir and print success while the
// surviving env vars point at paths that no longer exist.
func TestRemoveAgentEnvRefusesJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	orig := "// user comment\n{\"env\": {\"AKASHA_AGENT_ID\": \"claude\"}}\n"
	os.WriteFile(path, []byte(orig), 0600)

	target := &envTarget{path: path, keys: []string{"env"}}
	changed, err := removeAgentEnv(target)
	if err == nil {
		t.Fatal("expected an error, not an indistinguishable 'nothing to remove'")
	}
	if changed {
		t.Fatal("nothing was removed, so changed must be false")
	}
	// The precious file must be untouched.
	data, _ := os.ReadFile(path)
	if string(data) != orig {
		t.Fatal("JSONC settings file was modified")
	}
	// The error must name the file and tell the user what to do by hand.
	for _, want := range []string{shorten(path), "AKASHA_", "$EDITOR"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should carry manual instructions (%q): %v", want, err)
		}
	}
}

// Same shape in the MCP-entry remover: a stale "akasha" server pointing at a
// deleted binary must be reported, never silently left behind.
func TestRemoveJSONMCPRefusesJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	orig := "// user comment\n{\"servers\": {\"akasha\": {\"command\": \"akasha\"}}}\n"
	os.WriteFile(path, []byte(orig), 0600)

	changed, err := removeJSONMCP(path, "servers")
	if err == nil {
		t.Fatal("expected an error, not an indistinguishable 'nothing to remove'")
	}
	if changed {
		t.Fatal("nothing was removed, so changed must be false")
	}
	data, _ := os.ReadFile(path)
	if string(data) != orig {
		t.Fatal("JSONC config file was modified")
	}
	for _, want := range []string{shorten(path), `"akasha"`, "$EDITOR"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should carry manual instructions (%q): %v", want, err)
		}
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
