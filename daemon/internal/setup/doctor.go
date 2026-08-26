package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// HealthState is the resync-relevant state of one MCP client's akasha key.
type HealthState int

const (
	HealthOK         HealthState = iota // key present and valid
	HealthDesynced                      // key not in the vault registry — safe to re-mint
	HealthRevoked                       // key deliberately revoked — must NOT auto-repair
	HealthNoKey                         // akasha entry present but carries no --api-key
	HealthUnparsable                    // akasha entry present but its args couldn't be read
)

// AgentHealth reports one MCP client's akasha credential state.
type AgentHealth struct {
	Client  string // human label, e.g. "Claude Code"
	ID      string // client id for `agent resync <id>`, e.g. "claude"
	CfgPath string // config file inspected (~-shortened for display by callers)
	AgentID string // configured --agent-id (may be empty if unparseable)
	State   HealthState
}

// Resyncable reports whether repairing this client by re-minting its key is the
// correct action. A deliberately revoked key is intentionally excluded: silently
// re-minting it would defeat revocation, the one thing the vault must not do.
func (h AgentHealth) Resyncable() bool {
	return h.State == HealthDesynced || h.State == HealthNoKey
}

// keyVerifier is the slice of the vault that CheckAgents needs, so the check
// logic can be tested without a real keychain-backed vault.
type keyVerifier interface {
	VerifyAgentKey(plaintext string) (agentID string, err error)
}

// resyncVault is the slice of the vault that ResyncClient needs.
type resyncVault interface {
	// RegisterAgentKey re-admits an existing key (no rotation, no restart).
	RegisterAgentKey(agentID, plaintext string) error
	// CreateAgentKey mints a fresh key (used only on rotate / no-key fallback).
	CreateAgentKey(agentID string) (keyID, plaintext string, err error)
	// RevokeAgentKeyByValue retires the key a config previously held, so a
	// rotation actually replaces the old credential instead of adding one.
	RevokeAgentKeyByValue(plaintext string) error
}

// ResyncResult reports what ResyncClient did, so callers can tell the user
// whether an IDE restart is required.
type ResyncResult struct {
	Label   string // human label, e.g. "Claude Code"
	AgentID string
	Rotated bool // a new key was minted (config changed → IDE restart needed)
}

// CheckAgents inspects every installed MCP client that has an akasha entry and
// verifies its configured key against the vault. Clients with no akasha entry
// are skipped — there is nothing to be out of sync. The result drives both the
// `akasha status` warning and `akasha agent resync`.
func CheckAgents(v keyVerifier) []AgentHealth {
	var out []AgentHealth
	for _, c := range mcpClients {
		args, env, ok := c.readAkashaEntry()
		if !ok {
			continue // client not configured for akasha — nothing to check
		}
		h := AgentHealth{Client: c.label, ID: c.id, CfgPath: c.cfgPath}
		agentID, _, parsed := agentIDAndKey(args)
		apiKey := configuredKey(args, env)
		h.AgentID = agentID
		switch {
		case !parsed:
			h.State = HealthUnparsable
		case apiKey == "":
			h.State = HealthNoKey
		default:
			_, err := v.VerifyAgentKey(apiKey)
			switch {
			case err == nil:
				h.State = HealthOK
			case errors.Is(err, vault.ErrAgentKeyRevoked):
				h.State = HealthRevoked
			default: // ErrAgentKeyInvalid or any lookup error → treat as desynced
				h.State = HealthDesynced
			}
		}
		out = append(out, h)
	}
	return out
}

// ResyncClient repairs one MCP client's agent key.
//
// Default (rotate=false): re-admit the key already in the client's config, so
// the running MCP server keeps working with NO restart. This is the common,
// low-friction repair after a vault rebuild — and what an agent can trigger
// itself from the 401 error text.
//
// rotate=true (or no usable key in the config) mints a fresh key and rewrites
// the config; the IDE must then be restarted to pick it up. Use rotate only
// when the existing key may be compromised.
func ResyncClient(v resyncVault, binary, clientID string, rotate bool) (ResyncResult, error) {
	for _, c := range mcpClients {
		if c.id != clientID {
			continue
		}
		agentID := c.id
		var existingKey string
		if args, env, ok := c.readAkashaEntry(); ok {
			if key := configuredKey(args, env); key != "" {
				existingKey = key
			}
			if id, _, _ := agentIDAndKey(args); id != "" {
				agentID = id
			}
		}

		// Preferred path: re-admit the existing key. No config write, no restart.
		if !rotate && existingKey != "" {
			if err := v.RegisterAgentKey(agentID, existingKey); err != nil {
				return ResyncResult{Label: c.label, AgentID: agentID}, err
			}
			return ResyncResult{Label: c.label, AgentID: agentID, Rotated: false}, nil
		}

		// Fallback / rotate: mint a new key and rewrite the config.
		_, key, err := v.CreateAgentKey(agentID)
		if err != nil {
			return ResyncResult{Label: c.label, AgentID: agentID}, fmt.Errorf("mint agent key: %w", err)
		}
		if err := c.configure(binary, key); err != nil {
			return ResyncResult{Label: c.label, AgentID: agentID}, fmt.Errorf("write %s config: %w", c.label, err)
		}
		// Retire the key this config used to hold. Rotation previously only
		// ADDED a key: the superseded one stayed valid forever, so a machine
		// accumulated one working impersonation credential per rotation, for an
		// agent that had stopped using it. Revoked only after the new config is
		// safely written, so a failed write cannot leave the client with no
		// usable key.
		if existingKey != "" && existingKey != key {
			if err := v.RevokeAgentKeyByValue(existingKey); err != nil {
				return ResyncResult{Label: c.label, AgentID: agentID}, fmt.Errorf("revoke superseded key: %w", err)
			}
		}
		return ResyncResult{Label: c.label, AgentID: agentID, Rotated: true}, nil
	}
	return ResyncResult{}, fmt.Errorf("unknown MCP client %q", clientID)
}

// readAkashaEntry returns the akasha MCP server's args and env block for this
// client, or ok=false if the client has no akasha entry configured. It parses
// the two config shapes setup writes: JSON (mcpServers.akasha.{args,env}) and
// TOML ([mcp_servers.akasha] args = [...] / env = { ... }).
func (c mcpClient) readAkashaEntry() (args []string, env map[string]string, ok bool) {
	data, err := os.ReadFile(expand(c.cfgPath))
	if err != nil || len(data) == 0 {
		return nil, nil, false
	}
	switch c.format {
	case "json":
		return akashaEntryFromJSON(data, c.jsonKeyOrDefault())
	case "toml":
		return akashaEntryFromTOML(string(data))
	default:
		return nil, nil, false
	}
}

// akashaEntryFromJSON pulls the akasha server's args and env out of the given
// top-level object (key: "mcpServers" for most clients, "servers" for VS Code).
func akashaEntryFromJSON(data []byte, key string) ([]string, map[string]string, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, false
	}
	blob, ok := raw[key]
	if !ok {
		return nil, nil, false
	}
	var servers map[string]struct {
		Args []string          `json:"args"`
		Env  map[string]string `json:"env"`
	}
	if err := json.Unmarshal(blob, &servers); err != nil {
		return nil, nil, false
	}
	srv, ok := servers["akasha"]
	if !ok {
		return nil, nil, false
	}
	return srv.Args, srv.Env, true
}

// configuredKey returns the agent key an entry carries. The env block is the
// current form; a `--api-key` argument is the form written before the key moved
// off the command line (see agentKeyEnv), and is still read so an install that
// predates the change keeps working and keeps being repairable until the next
// `akasha setup` rewrites it.
func configuredKey(args []string, env map[string]string) string {
	if k := env[agentKeyEnv]; k != "" {
		return k
	}
	_, k, _ := agentIDAndKey(args)
	return k
}

// akashaEntryFromTOML extracts the args array and the env table from the
// [mcp_servers.akasha] block. Hand-parsed to match the hand-written writer in
// writeTOMLMCP (no TOML dependency). Returns the entry as present-but-unparsable
// (nil args, true) if the block exists but its args line can't be read, so a
// malformed config still surfaces as a warning rather than being silently
// skipped.
func akashaEntryFromTOML(s string) ([]string, map[string]string, bool) {
	idx := strings.Index(s, "[mcp_servers.akasha]")
	if idx < 0 {
		return nil, nil, false
	}
	block := s[idx+len("[mcp_servers.akasha]"):]
	// Stop at the next table header so we only read this block's lines.
	if next := strings.Index(block, "\n["); next >= 0 {
		block = block[:next]
	}
	var args []string
	env := map[string]string{}
	argsSeen, argsBad := false, false
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if rest, found := strings.CutPrefix(line, "args"); found {
			argsSeen = true
			open := strings.Index(rest, "[")
			close := strings.LastIndex(rest, "]")
			if open < 0 || close <= open {
				argsBad = true
				continue
			}
			for _, tok := range strings.Split(rest[open+1:close], ",") {
				tok = strings.TrimSpace(tok)
				tok = strings.Trim(tok, `"`)
				if tok != "" {
					args = append(args, tok)
				}
			}
			continue
		}
		if rest, found := strings.CutPrefix(line, "env"); found {
			open := strings.Index(rest, "{")
			close := strings.LastIndex(rest, "}")
			if open < 0 || close <= open {
				continue
			}
			for _, pair := range strings.Split(rest[open+1:close], ",") {
				k, v, split := strings.Cut(pair, "=")
				if !split {
					continue
				}
				k = strings.TrimSpace(k)
				v = strings.Trim(strings.TrimSpace(v), `"`)
				if k != "" {
					env[k] = v
				}
			}
		}
	}
	if !argsSeen || argsBad {
		return nil, env, true // block present, args missing or malformed
	}
	return args, env, true
}

// agentIDAndKey pulls the --agent-id and --api-key values out of an args slice
// of the form ["mcp", "--agent-id", X, "--api-key", Y]. parsed is false only
// when the slice doesn't look like an akasha mcp invocation at all.
func agentIDAndKey(args []string) (agentID, apiKey string, parsed bool) {
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "--agent-id":
			agentID = args[i+1]
		case "--api-key":
			apiKey = args[i+1]
		}
	}
	parsed = len(args) > 0
	return agentID, apiKey, parsed
}
