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

	// EnvPath is the harness env file this client's sessions read their key
	// from, when it has one. Separate from CfgPath because they are separate
	// files that setup writes together and everything else touched singly.
	EnvPath string
	// EnvKeyStale reports that EnvPath carries an akasha key the vault will not
	// accept. It is deliberately NOT folded into State: the common shape of this
	// failure is a HEALTHY config beside a dead environment, so a single field
	// would report OK and hide it -- which is exactly what happened.
	EnvKeyStale bool
}

// Resyncable reports whether repairing this client by re-minting its key is the
// correct action. A deliberately revoked key is intentionally excluded: silently
// re-minting it would defeat revocation, the one thing the vault must not do.
func (h AgentHealth) Resyncable() bool {
	return h.State == HealthDesynced || h.State == HealthNoKey
}

// NeedsEnvRepair reports a client whose CONFIG is fine but whose harness env
// carries a key the vault will not accept.
//
// Separate from Resyncable because the shapes differ: Resyncable describes a
// broken config, this describes a healthy config beside a dead session. Anything
// keyed only on State misses it, which is how it went unnoticed -- `status`
// printed a clean bill of health for a machine whose agent could not
// authenticate a single CLI call.
func (h AgentHealth) NeedsEnvRepair() bool { return h.EnvKeyStale }

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
	// EnvUpdated reports that the harness env file was rewritten too, not just
	// the MCP config. Both or neither -- see the rotate path.
	EnvUpdated bool
	Label      string // human label, e.g. "Claude Code"
	AgentID    string
	Rotated    bool // a new key was minted (config changed → IDE restart needed)
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
		// The other file. An agent reads its key from the harness environment,
		// not from the MCP config, so a config that verifies says nothing about
		// whether the session can authenticate.
		if t := c.envTargetFor(); t != nil {
			if env, ok := readAgentEnv(t); ok {
				if k := env[agentKeyEnv]; k != "" {
					h.EnvPath = t.path
					if _, err := v.VerifyAgentKey(k); err != nil {
						h.EnvKeyStale = true
					}
				}
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
			// And repair the harness env if it drifted from the config.
			//
			// This is the non-destructive remedy, and it did not exist. The only
			// advertised repair was --rotate, which mints a NEW key -- so the
			// answer to "my env file holds a dead key" was a command that
			// replaced the live one as well. Writing the config's own key into
			// the env file fixes the actual fault and invalidates nothing.
			envUpdated := false
			if t := c.envTargetFor(); t != nil {
				if cur, ok := readAgentEnv(t); ok && cur[agentKeyEnv] != "" && cur[agentKeyEnv] != existingKey {
					if err := injectAgentEnv(t, map[string]string{agentKeyEnv: existingKey}); err != nil {
						return ResyncResult{Label: c.label, AgentID: agentID},
							fmt.Errorf("re-admitted the key but could not update %s: %w", t.path, err)
					}
					envUpdated = true
				}
			}
			return ResyncResult{Label: c.label, AgentID: agentID, Rotated: false, EnvUpdated: envUpdated}, nil
		}

		// Fallback / rotate: mint a new key and rewrite the config.
		_, key, err := v.CreateAgentKey(agentID)
		if err != nil {
			return ResyncResult{Label: c.label, AgentID: agentID}, fmt.Errorf("mint agent key: %w", err)
		}
		if err := c.configure(binary, key); err != nil {
			return ResyncResult{Label: c.label, AgentID: agentID}, fmt.Errorf("write %s config: %w", c.label, err)
		}
		// The key lives in TWO files, and rotation used to write one of them.
		//
		// setup mints a key and puts it in the MCP config AND in the harness env
		// target (~/.claude/settings.json and friends), because env ownership is
		// the mechanism that actually routes an agent's shell through akasha.
		// configure() writes only c.cfgPath. So `agent resync --rotate` wrote the
		// new key to the MCP config, then revoked the value the env file still
		// held -- and every CLI call from that session began authenticating as a
		// revoked key while `status` reported the client healthy.
		//
		// That made the DOCUMENTED repair destroy the one mechanism measured to
		// change agent behaviour. Fixing the config and breaking the environment
		// is not a repair.
		//
		// Only the key is injected here, not a regenerated agent dir: rotation is
		// about the credential, and rewriting a user's provider stubs as a side
		// effect of it is a different operation they did not ask for.
		envUpdated := false
		if t := c.envTargetFor(); t != nil {
			// "Absent" and "present but unreadable" are different answers, and
			// collapsing them is how the revoke below gets to run against a file
			// nobody checked. A settings file with comments in it (VS Code
			// tolerates JSONC) parses as neither, so treating that as "no key
			// here" would revoke the key it very likely still holds.
			if _, statErr := os.Stat(expand(t.path)); statErr == nil {
				cur, ok := readAgentEnv(t)
				if !ok {
					return ResyncResult{Label: c.label, AgentID: agentID, Rotated: true},
						fmt.Errorf("wrote the %s config, but %s could not be read as plain JSON, "+
							"so its key could not be updated.\n"+
							"  The previous key was NOT revoked — that session still works. Set %s "+
							"there by hand, or remove the comments and re-run.", c.label, t.path, agentKeyEnv)
				}
				if cur[agentKeyEnv] != "" {
					if err := injectAgentEnv(t, map[string]string{agentKeyEnv: key}); err != nil {
						// Do NOT fall through to the revoke below. The config now
						// holds a working key and the env holds the old one; if the
						// old one is then revoked, the session is dead with no way
						// back. Leaving both keys valid is the strictly better
						// failure, and it is recoverable by re-running.
						return ResyncResult{Label: c.label, AgentID: agentID, Rotated: true},
							fmt.Errorf("wrote the %s config but could not update %s: %w\n"+
								"  The previous key was NOT revoked, so the session still works. "+
								"Fix that file's permissions and re-run.", c.label, t.path, err)
					}
					envUpdated = true
				}
			}
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
		return ResyncResult{Label: c.label, AgentID: agentID, Rotated: true, EnvUpdated: envUpdated}, nil
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
