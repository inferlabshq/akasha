package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ShadowClaudeConfig builds the Claude Code configuration a run's agent sees:
// a directory, inside the run dir, that the child is pointed at with
// CLAUDE_CONFIG_DIR. It returns "" when there is no Claude Code configuration
// to shadow.
//
// WHY. Setup writes akasha's agent key into two Claude Code files —
// settings.json (env injection) and ~/.claude.json (the MCP server's env
// block) — so a run masks both, or an agent inside could read a persistent key
// and use it outside the run's capability profile. Masking alone cost the user
// their Claude configuration inside every run, and on macOS, where a masked
// file reads as EPERM rather than empty, Claude Code opened every run on a
// "Settings Error" dialog. seatbelt cannot bind a scrubbed file over the
// original, but Claude Code can be pointed at a different directory, so the
// run gets the user's configuration with akasha's own variables taken out.
//
// WHAT IS IN IT. Every entry of the real config directory as a symlink —
// history, projects, plugins and the rest stay live and writes persist — except
// the two key-bearing files, which are scrubbed COPIES: every "env" map in
// them loses the variables setup injected (isAkashaOwnedEnv: AKASHA_*, or a
// value pointing into the akasha agent directory). The run's own
// AKASHA_AGENT_KEY and broker wiring therefore stand. Changes Claude makes to
// the two copies during a run do not reach the originals.
//
// The originals stay masked. Nothing here weakens the deny set; it only stops
// the harness from needing to read what the deny set hides.
func ShadowClaudeConfig(runDir string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", nil
	}
	src := os.Getenv("CLAUDE_CONFIG_DIR")
	global := filepath.Join(src, ".claude.json")
	if src == "" {
		src = filepath.Join(home, ".claude")
		global = filepath.Join(home, ".claude.json")
	}
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		return "", nil // Claude Code is not configured here
	}

	dst := filepath.Join(runDir, "claude-config")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", fmt.Errorf("claude config for the run: %w", err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return "", fmt.Errorf("claude config for the run: %w", err)
	}
	for _, e := range ents {
		name := e.Name()
		if name == "settings.json" || name == ".claude.json" {
			continue
		}
		if err := os.Symlink(filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return "", fmt.Errorf("claude config for the run: %w", err)
		}
	}
	for from, to := range map[string]string{
		filepath.Join(src, "settings.json"): filepath.Join(dst, "settings.json"),
		global:                              filepath.Join(dst, ".claude.json"),
	} {
		if err := writeScrubbedJSON(from, to); err != nil {
			return "", fmt.Errorf("claude config for the run: %w", err)
		}
	}
	return dst, nil
}

// writeScrubbedJSON copies a JSON file with akasha's injected variables
// removed from every "env" map in it. A missing source writes nothing. A
// source that is not plain JSON writes nothing either: the harness then sees
// its defaults for that file, which is the old behaviour, rather than a copy
// that might still carry a key.
func writeScrubbedJSON(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil || len(data) == 0 {
		return nil
	}
	var doc interface{}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	scrubEnvMaps(doc, agentsBase()+string(os.PathSeparator))
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(to, out, 0o600)
}

// scrubEnvMaps walks a decoded JSON document and drops akasha-owned variables
// from every object found under an "env" key, at any depth: settings.json's
// top-level env, and each mcpServers.<name>.env in ~/.claude.json, including
// per-project server lists.
func scrubEnvMaps(node interface{}, agentsPrefix string) {
	switch n := node.(type) {
	case map[string]interface{}:
		for k, v := range n {
			if env, ok := v.(map[string]interface{}); ok && k == "env" {
				for name, val := range env {
					if isAkashaOwnedEnv(name, val, agentsPrefix) {
						delete(env, name)
					}
				}
			}
			scrubEnvMaps(v, agentsPrefix)
		}
	case []interface{}:
		for _, v := range n {
			scrubEnvMaps(v, agentsPrefix)
		}
	}
}
