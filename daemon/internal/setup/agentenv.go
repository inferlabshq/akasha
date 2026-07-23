package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/inferlabshq/akasha/internal/template"
)

// Agent environment ownership: instead of agents reading plaintext provider
// configs (or politely opting in to MCP tools), setup points each agent
// HARNESS's sessions at daemon-managed config. For AWS that means every
// `aws` CLI/SDK call inside an agent session resolves through
// `akasha helper` (credential_process) — per-call audit and agent identity —
// while the human's own ~/.aws files stay untouched.
//
// Two pieces per agent:
//  1. ~/.akasha/agents/<agent-id>/ holds generated provider config stubs
//     (e.g. aws.config with a credential_process line per vaulted instance).
//  2. The harness settings file gets env vars routing provider tooling at
//     those stubs, plus AKASHA_AGENT_ID/KEY so helper calls authenticate as
//     the agent.

// agentsBase returns the parent dir for per-agent generated config.
func agentsBase() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "agents")
}

// writeAgentDir generates ~/.akasha/agents/<agentID>/ from every provider
// template that declares an agent block: the env map to inject (returned)
// and the per-instance config stubs (written). instancesOf lists the vaulted
// instances for a provider (label names), letting tests stub the daemon.
//
// Owning an agent session's environment is a high-trust effect (see
// internal/trust), so a provider's agent block is applied only if trusted
// reports it approved. Untrusted providers are collected and returned in
// skipped so the caller can tell the user what to approve — nothing is wired
// silently.
func writeAgentDir(agentID, binary string, trusted func(*template.Template) bool, instancesOf func(provider string) []string) (env map[string]string, skipped []string, err error) {
	dir := filepath.Join(agentsBase(), agentID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}

	env = map[string]string{
		"AKASHA_AGENT_ID": agentID,
	}

	for _, t := range template.Providers() {
		if t.Agent == nil {
			continue
		}
		if !trusted(t) {
			skipped = append(skipped, t.Name)
			continue
		}
		instances := instancesOf(t.Name)
		sort.Strings(instances)
		for _, d := range t.Agent.Own {
			r := renderOwn(d, t.Name, binary, dir, instances)
			env[r.envName] = r.envValue // path into the agent dir — always set
			if r.write {
				if err := os.WriteFile(r.path, r.content, 0600); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	return env, skipped, nil
}

// envTarget describes where a harness keeps session environment variables.
type envTarget struct {
	path string // settings file (~ expanded by caller)
	keys []string
	// keys is the nested-object path to the env map, e.g.
	//   ["env"]                              Claude Code settings.json
	//   ["terminal.integrated.env.osx"]      VS Code-family settings.json
}

// envTargetFor returns where (and how) to inject session env for a client,
// or nil if the harness has no supported mechanism yet.
func (c mcpClient) envTargetFor() *envTarget {
	switch c.id {
	case "claude":
		// Claude Code applies settings "env" to every session, including
		// each Bash tool call — the strongest harness hook available.
		return &envTarget{path: "~/.claude/settings.json", keys: []string{"env"}}
	case "vscode", "vscode-insiders", "cursor":
		// VS Code-family: integrated terminal env, which is where Copilot /
		// Cursor agent shells run. Settings live next to (or near) the MCP
		// config dir.
		var base string
		switch c.id {
		case "vscode":
			base = strings.TrimSuffix(c.cfgPath, "/mcp.json")
		case "vscode-insiders":
			base = strings.TrimSuffix(c.cfgPath, "/mcp.json")
		case "cursor":
			switch runtime.GOOS {
			case "darwin":
				base = "~/Library/Application Support/Cursor/User"
			case "linux":
				base = "~/.config/Cursor/User"
			default:
				return nil
			}
		}
		osKey := "terminal.integrated.env.linux"
		if runtime.GOOS == "darwin" {
			osKey = "terminal.integrated.env.osx"
		}
		return &envTarget{path: base + "/settings.json", keys: []string{osKey}}
	default:
		return nil
	}
}

// injectAgentEnv merges env into the client's settings file at the target's
// key path, preserving everything else. Settings files are user-owned and
// precious: if the existing content does not parse as JSON (e.g. JSONC with
// comments), we refuse to touch it and tell the user what to add — never
// clobber.
func injectAgentEnv(t *envTarget, env map[string]string) error {
	path := expand(t.path)
	cfg := map[string]interface{}{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("%s is not plain JSON (comments?) — add these to %s manually: %s",
				path, strings.Join(t.keys, "."), summarizeEnv(env))
		}
	}

	node := cfg
	for _, k := range t.keys[:len(t.keys)-1] {
		child, _ := node[k].(map[string]interface{})
		if child == nil {
			child = map[string]interface{}{}
			node[k] = child
		}
		node = child
	}
	leaf := t.keys[len(t.keys)-1]
	envMap, _ := node[leaf].(map[string]interface{})
	if envMap == nil {
		envMap = map[string]interface{}{}
	}
	for k, v := range env {
		envMap[k] = v
	}
	node[leaf] = envMap

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// removeAgentEnv strips the akasha-owned variables this client's settings file
// — the inverse of injectAgentEnv. It is value-aware: a variable is removed
// only when it is namespaced (AKASHA_*) or its value points into the akasha
// agent directory (~/.akasha/agents/). A user's own AWS_CONFIG_FILE or similar,
// pointing elsewhere, is left untouched. Returns (changed, error).
func removeAgentEnv(t *envTarget) (bool, error) {
	path := expand(t.path)
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false, nil
	}
	cfg := map[string]interface{}{}
	if json.Unmarshal(data, &cfg) != nil {
		return false, nil // malformed (comments?) → don't risk clobbering
	}

	// Navigate to the env map without creating any missing parents.
	node := cfg
	for _, k := range t.keys[:len(t.keys)-1] {
		child, ok := node[k].(map[string]interface{})
		if !ok {
			return false, nil
		}
		node = child
	}
	leaf := t.keys[len(t.keys)-1]
	envMap, ok := node[leaf].(map[string]interface{})
	if !ok {
		return false, nil
	}

	agentsPrefix := agentsBase() + string(os.PathSeparator)
	changed := false
	for k, v := range envMap {
		if isAkashaOwnedEnv(k, v, agentsPrefix) {
			delete(envMap, k)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	if len(envMap) == 0 {
		delete(node, leaf)
	} else {
		node[leaf] = envMap
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(path, out, 0600)
}

// isAkashaOwnedEnv reports whether an env var was injected by akasha setup and
// is therefore safe to remove on uninstall: either AKASHA_*-namespaced, or a
// string value pointing into the akasha agent directory.
func isAkashaOwnedEnv(key string, value interface{}, agentsPrefix string) bool {
	if strings.HasPrefix(key, "AKASHA_") {
		return true
	}
	s, ok := value.(string)
	return ok && strings.HasPrefix(s, agentsPrefix)
}

func summarizeEnv(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%s", k, env[k])
	}
	return strings.Join(parts, " ")
}
