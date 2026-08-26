package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// mcpClient describes an MCP-capable IDE/agent and how to configure it.
// Every MCP client spawns the same `akasha mcp` stdio server — only the
// config file location and format differ. Each client gets its own agent
// identity so the audit log can attribute actions per-tool.
type mcpClient struct {
	id      string // agent-id + --providers selector
	label   string
	dir     string // directory whose existence means "installed" (~ expanded)
	cfgPath string // config file to write (~ expanded)
	format  string // "json" or "toml"
	jsonKey string // top-level object key for JSON configs ("" => "mcpServers")
}

// mcpClients is the registry. Adding an IDE is one entry here.
var mcpClients = func() []mcpClient {
	cs := []mcpClient{
		{id: "claude", label: "Claude Code", dir: "~/.claude", cfgPath: "~/.claude.json", format: "json"},
		{id: "cursor", label: "Cursor", dir: "~/.cursor", cfgPath: "~/.cursor/mcp.json", format: "json"},
		{id: "windsurf", label: "Windsurf", dir: "~/.codeium/windsurf", cfgPath: "~/.codeium/windsurf/mcp_config.json", format: "json"},
		{id: "codex", label: "Codex", dir: "~/.codex", cfgPath: "~/.codex/config.toml", format: "toml"},
	}
	return append(cs, vscodeClients()...)
}()

// vscodeClients returns the VS Code (stable + Insiders) MCP targets with
// OS-resolved paths. VS Code keeps user-level MCP servers in mcp.json under a
// top-level "servers" key — a different shape from the Claude/Cursor
// "mcpServers" — so Copilot agent mode (and the subagents it spawns) pick up
// the akasha server. Windows (%APPDATA%) isn't handled by expand() yet.
func vscodeClients() []mcpClient {
	var stable, insiders string
	switch runtime.GOOS {
	case "darwin":
		stable = "~/Library/Application Support/Code/User"
		insiders = "~/Library/Application Support/Code - Insiders/User"
	case "linux":
		stable = "~/.config/Code/User"
		insiders = "~/.config/Code - Insiders/User"
	default:
		return nil
	}
	return []mcpClient{
		{id: "vscode", label: "VS Code (Copilot)", dir: stable, cfgPath: stable + "/mcp.json", format: "json", jsonKey: "servers"},
		{id: "vscode-insiders", label: "VS Code Insiders", dir: insiders, cfgPath: insiders + "/mcp.json", format: "json", jsonKey: "servers"},
	}
}

// jsonKeyOrDefault is the top-level key for this client's JSON config. Most
// clients use "mcpServers"; VS Code uses "servers".
func (c mcpClient) jsonKeyOrDefault() string {
	if c.jsonKey != "" {
		return c.jsonKey
	}
	return "mcpServers"
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

// installed reports whether the client appears to be present on this machine.
func (c mcpClient) installed() bool {
	if _, err := os.Stat(expand(c.dir)); err == nil {
		return true
	}
	// Claude Code may have only the JSON file, not the dir.
	if _, err := os.Stat(expand(c.cfgPath)); err == nil {
		return true
	}
	return false
}

// agentKeyEnv is the variable `akasha mcp` reads its agent key from.
//
// The key travels in the client's env block rather than on its command line
// because argv is public: `ps` and /proc/<pid>/cmdline are readable by every
// process on the machine, other users' included, so a key in args was legible
// to anything that could list processes — and the agent whose Bash tool ran
// `ps` was itself one of them. Lifting another client's key that way buys a
// working identity, which defeats per-agent attribution in the audit log and
// makes `akasha agent revoke` revoke the wrong thing.
//
// This does not make the key private, and is not meant to: /proc/<pid>/environ
// is readable by the same uid, and agents run as the user. It moves the
// exposure from "anyone on the box" back to the same-uid ceiling the rest of
// the identity model already assumes and states
// (docs/design/same-user-identity.md) — where the containment answer is
// `akasha run`'s DenyPeerProcesses, not the key registry. The file the env
// block lives in has to hold that same line, which is what writeKeyedConfig is
// for: a config the client created is 0644, and moving a key out of argv into a
// world-readable file is not the move it claims to be.
const agentKeyEnv = "AKASHA_AGENT_KEY"

// writeKeyedConfig writes a client config that now holds a live agent key, and
// makes sure the file's mode says so.
//
// os.WriteFile applies its mode only when it CREATES the file, and these files
// normally exist already: the client wrote them, at 0644 under a default umask.
// So the key moved out of argv and landed in a world-readable file — which is
// not the ceiling the comment on agentKeyEnv claims. A home directory is
// usually 0700 and hides it in practice, but "usually" is not a property a
// threat model can rest on, and the chmod costs nothing.
func writeKeyedConfig(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// configure writes the akasha MCP entry into this client's config file.
func (c mcpClient) configure(binary, apiKey string) error {
	path := expand(c.cfgPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	args := []string{"mcp", "--agent-id", c.id}
	env := map[string]string{agentKeyEnv: apiKey}
	switch c.format {
	case "json":
		server := map[string]interface{}{"command": binary, "args": args, "env": env}
		// VS Code's schema wants an explicit stdio transport type.
		if c.jsonKey == "servers" {
			server["type"] = "stdio"
		}
		return writeJSONMCP(path, c.jsonKeyOrDefault(), server)
	case "toml":
		return writeTOMLMCP(path, binary, args, env)
	default:
		return fmt.Errorf("unknown config format %q", c.format)
	}
}

// writeJSONMCP merges an "akasha" server into the given top-level object (key:
// "mcpServers" for most clients, "servers" for VS Code) of a JSON config file,
// preserving anything already there.
//
// A file we cannot parse is an ERROR, not something to overwrite: VS Code's
// mcp.json is canonically JSONC, so rewriting whatever we managed to unmarshal
// would drop the user's comments and every server we failed to parse.
func writeJSONMCP(path, key string, server map[string]interface{}) error {
	cfg := map[string]interface{}{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if json.Unmarshal(data, &cfg) != nil {
			// The snippet carries a live agent key, because the key is stored
			// hashed and cannot be read back — an error that redacted it would
			// leave the user unable to finish the step it is asking them to do.
			// Say so, so it does not get pasted into an issue.
			entry, _ := json.Marshal(map[string]interface{}{"akasha": server})
			return fmt.Errorf("%s is not plain JSON (comments?) — add this inside %q by hand:\n       %s\n"+
				"       (contains a live agent key — do not paste it anywhere public)",
				shorten(path), key, entry)
		}
	}
	servers, _ := cfg[key].(map[string]interface{})
	if servers == nil {
		servers = map[string]interface{}{}
	}
	servers["akasha"] = server
	cfg[key] = servers

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeKeyedConfig(path, out)
}

// deconfigure removes the akasha MCP entry this client's config — the inverse
// of configure. It only ever touches the namespaced "akasha" server, leaving
// every other server the user configured untouched. Returns (changed, error):
// changed is false when there was no akasha entry to remove.
func (c mcpClient) deconfigure() (bool, error) {
	path := expand(c.cfgPath)
	switch c.format {
	case "json":
		return removeJSONMCP(path, c.jsonKeyOrDefault())
	case "toml":
		return removeTOMLMCP(path)
	default:
		return false, fmt.Errorf("unknown config format %q", c.format)
	}
}

// removeJSONMCP deletes the "akasha" server from the given top-level object of a
// JSON config, preserving every other server. If that leaves the server object
// empty, the object key is removed too, so the file is left as setup found it.
//
// A file we cannot parse is an ERROR, not a silent no-op: the entry names a
// binary uninstall is about to remove, so the user has to be told.
func removeJSONMCP(path, key string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false, nil // no file → nothing to remove
	}
	cfg := map[string]interface{}{}
	if json.Unmarshal(data, &cfg) != nil {
		return false, fmt.Errorf("%s is not plain JSON (comments?) — delete the \"akasha\" entry under %q by hand:\n       $EDITOR %s", shorten(path), key, shorten(path))
	}
	servers, ok := cfg[key].(map[string]interface{})
	if !ok {
		return false, nil
	}
	if _, present := servers["akasha"]; !present {
		return false, nil
	}
	delete(servers, "akasha")
	if len(servers) == 0 {
		delete(cfg, key)
	} else {
		cfg[key] = servers
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(path, out, 0600)
}

// removeTOMLMCP strips the [mcp_servers.akasha] block from a TOML config: from
// its table header up to (but not including) the next table header or EOF.
func removeTOMLMCP(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false, nil
	}
	s := string(data)
	const header = "[mcp_servers.akasha]"
	idx := strings.Index(s, header)
	if idx < 0 {
		return false, nil
	}
	// Find the end of the block: the next "\n[" table header after ours.
	rest := s[idx+len(header):]
	end := len(s)
	if next := strings.Index(rest, "\n["); next >= 0 {
		end = idx + len(header) + next + 1 // keep the newline that precedes the next header
	}
	// Trim a single newline directly before our header so we don't leave a gap.
	start := idx
	if start > 0 && s[start-1] == '\n' {
		start--
	}
	cleaned := s[:start] + s[end:]
	return true, os.WriteFile(path, []byte(cleaned), 0600)
}

// writeTOMLMCP writes the [mcp_servers.akasha] block into a TOML config,
// REPLACING any block already there. Hand-written to avoid a TOML dependency.
//
// It used to return early whenever a block existed, which quietly broke every
// path that changes the key: `setup` and `agent resync --rotate` mint a new key,
// write the config, then revoke the old one — so for Codex the write was a
// no-op and the config was left holding the credential that had just been
// revoked. Replacing is also what lets an existing install migrate off the old
// `--api-key` argument form.
func writeTOMLMCP(path, binary string, args []string, env map[string]string) error {
	if _, err := removeTOMLMCP(path); err != nil {
		return err
	}
	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}
	// Build args as a TOML array of strings.
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	block := fmt.Sprintf("\n[mcp_servers.akasha]\ncommand = %q\nargs = [%s]\n",
		binary, strings.Join(quoted, ", "))
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic output, so a rewrite is a clean diff
		pairs := make([]string, len(keys))
		for i, k := range keys {
			pairs[i] = fmt.Sprintf("%s = %q", k, env[k])
		}
		block += fmt.Sprintf("env = { %s }\n", strings.Join(pairs, ", "))
	}

	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return writeKeyedConfig(path, []byte(existing+block))
}
