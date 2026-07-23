package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/internal/vault"
)

// fakeVault implements keyVerifier + resyncVault for testing the doctor logic
// without a real keychain-backed vault.
type fakeVault struct {
	valid      map[string]string // apiKey → agentID (verifies OK)
	revoked    map[string]bool   // apiKey → revoked
	minted     []string          // agent IDs CreateAgentKey was called for
	readmitted []string          // "agentID:key" pairs RegisterAgentKey saw
}

func (f *fakeVault) VerifyAgentKey(key string) (string, error) {
	if f.revoked[key] {
		return "", vault.ErrAgentKeyRevoked
	}
	if id, ok := f.valid[key]; ok {
		return id, nil
	}
	return "", vault.ErrAgentKeyInvalid
}

func (f *fakeVault) CreateAgentKey(agentID string) (string, string, error) {
	f.minted = append(f.minted, agentID)
	return "agt_" + agentID + "_new", "agt_" + agentID + "_new", nil
}

func (f *fakeVault) RegisterAgentKey(agentID, key string) error {
	if f.revoked[key] {
		return vault.ErrAgentKeyRevoked
	}
	f.readmitted = append(f.readmitted, agentID+":"+key)
	if f.valid == nil {
		f.valid = map[string]string{}
	}
	f.valid[key] = agentID // re-admitted → now verifies OK
	return nil
}

// withClaudeConfig points the "claude" mcpClient at a temp config file and
// restores the registry afterward.
func withClaudeConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	orig := mcpClients
	t.Cleanup(func() { mcpClients = orig })
	mcpClients = []mcpClient{{id: "claude", label: "Claude Code", dir: dir, cfgPath: path, format: "json"}}
	return path
}

func stateFor(t *testing.T, hs []AgentHealth, id string) HealthState {
	t.Helper()
	for _, h := range hs {
		if h.ID == id {
			return h.State
		}
	}
	t.Fatalf("no health entry for %q", id)
	return 0
}

func TestCheckAgents_States(t *testing.T) {
	cfg := func(key string) string {
		return `{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude","--api-key","` + key + `"]}}}`
	}
	fv := &fakeVault{
		valid:   map[string]string{"agt_good": "claude"},
		revoked: map[string]bool{"agt_revoked": true},
	}

	cases := []struct {
		name string
		file string
		want HealthState
	}{
		{"valid", cfg("agt_good"), HealthOK},
		{"desynced", cfg("agt_orphan"), HealthDesynced},
		{"revoked", cfg("agt_revoked"), HealthRevoked},
		{"no key", `{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude"]}}}`, HealthNoKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withClaudeConfig(t, tc.file)
			got := stateFor(t, CheckAgents(fv), "claude")
			if got != tc.want {
				t.Errorf("state = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckAgents_SkipsUnconfigured(t *testing.T) {
	// Config file with no akasha entry → client is skipped entirely.
	withClaudeConfig(t, `{"mcpServers":{"github":{"command":"x","args":[]}}}`)
	if got := CheckAgents(&fakeVault{}); len(got) != 0 {
		t.Errorf("expected no health entries, got %d", len(got))
	}
	// Missing config file → also skipped (no panic).
	withClaudeConfig(t, "")
	if got := CheckAgents(&fakeVault{}); len(got) != 0 {
		t.Errorf("expected no health entries for missing file, got %d", len(got))
	}
}

func TestResyncable(t *testing.T) {
	// Only desync and no-key are auto-repairable; revoked must never be.
	if !(AgentHealth{State: HealthDesynced}).Resyncable() {
		t.Error("desynced should be resyncable")
	}
	if !(AgentHealth{State: HealthNoKey}).Resyncable() {
		t.Error("no-key should be resyncable")
	}
	if (AgentHealth{State: HealthRevoked}).Resyncable() {
		t.Error("revoked must NOT be resyncable — that would defeat revocation")
	}
	if (AgentHealth{State: HealthOK}).Resyncable() {
		t.Error("ok should not be resyncable")
	}
}

// Default resync re-admits the EXISTING key: config is untouched (no restart)
// and the same key is registered back into the vault.
func TestResyncClient_ReadmitsExistingKey(t *testing.T) {
	path := withClaudeConfig(t,
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude","--api-key","agt_orphan"]}}}`)
	fv := &fakeVault{}

	res, err := ResyncClient(fv, "/usr/local/bin/akasha", "claude", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Label != "Claude Code" || res.Rotated {
		t.Errorf("got %+v, want {Claude Code, Rotated:false}", res)
	}
	if len(fv.minted) != 0 {
		t.Errorf("expected no minting on re-admit, got %v", fv.minted)
	}
	if len(fv.readmitted) != 1 || fv.readmitted[0] != "claude:agt_orphan" {
		t.Errorf("expected re-admit of claude:agt_orphan, got %v", fv.readmitted)
	}
	// Config must be UNCHANGED — same key, so the running server needs no restart.
	data, _ := os.ReadFile(path)
	args, _ := akashaArgsFromJSON(data, "mcpServers")
	if _, apiKey, _ := agentIDAndKey(args); apiKey != "agt_orphan" {
		t.Errorf("config api-key = %q, want unchanged agt_orphan", apiKey)
	}
}

// --rotate mints a new key and rewrites the config (restart needed).
func TestResyncClient_RotateRewritesConfig(t *testing.T) {
	path := withClaudeConfig(t,
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude","--api-key","agt_orphan"]}}}`)
	fv := &fakeVault{}

	res, err := ResyncClient(fv, "/usr/local/bin/akasha", "claude", true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rotated {
		t.Error("expected Rotated=true on --rotate")
	}
	if len(fv.minted) != 1 || fv.minted[0] != "claude" {
		t.Errorf("expected one mint, got %v", fv.minted)
	}
	data, _ := os.ReadFile(path)
	args, _ := akashaArgsFromJSON(data, "mcpServers")
	if _, apiKey, _ := agentIDAndKey(args); apiKey != "agt_claude_new" {
		t.Errorf("config api-key = %q, want agt_claude_new", apiKey)
	}
}

// With no key in the config there's nothing to re-admit, so resync falls back
// to minting even without --rotate.
func TestResyncClient_NoKeyFallsBackToMint(t *testing.T) {
	withClaudeConfig(t,
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude"]}}}`)
	fv := &fakeVault{}

	res, err := ResyncClient(fv, "akasha", "claude", false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rotated || len(fv.minted) != 1 {
		t.Errorf("expected mint fallback, got %+v minted=%v", res, fv.minted)
	}
}

func TestResyncClient_UnknownClient(t *testing.T) {
	if _, err := ResyncClient(&fakeVault{}, "akasha", "nope", false); err == nil {
		t.Error("expected error for unknown client")
	}
}

// TestResyncRoundTrip_RealVault reproduces the actual user scenario against a
// real (test-isolated) vault: a config holding a key the vault doesn't know is
// reported HealthDesynced; after `resync` the SAME key verifies clean and the
// config is untouched — proving the no-restart repair works end to end.
func TestResyncRoundTrip_RealVault(t *testing.T) {
	const key = "agt_orphaned_key"
	path := withClaudeConfig(t,
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude","--api-key","`+key+`"]}}}`)
	before, _ := os.ReadFile(path)

	vlt, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()

	// Before: the stored key was never minted in this vault → desynced.
	if got := stateFor(t, CheckAgents(vlt), "claude"); got != HealthDesynced {
		t.Fatalf("before resync: state = %v, want HealthDesynced", got)
	}

	res, err := ResyncClient(vlt, "akasha", "claude", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rotated {
		t.Error("default resync should re-admit, not rotate")
	}

	// After: the existing key now verifies, and the config is byte-identical
	// (the running MCP server keeps using it — no restart).
	if got := stateFor(t, CheckAgents(vlt), "claude"); got != HealthOK {
		t.Fatalf("after resync: state = %v, want HealthOK", got)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("config changed on re-admit — would force an unnecessary restart")
	}
}

// A deliberately revoked key must not be re-admitted, even by an explicit
// resync — that would silently defeat revocation. --rotate is the escape hatch.
func TestResync_RevokedKeyRefused_RealVault(t *testing.T) {
	withClaudeConfig(t,
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude","--api-key","ignored"]}}}`)
	vlt, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()

	// Mint a real key, point the config at it, then revoke it.
	keyID, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	withClaudeConfig(t,
		`{"mcpServers":{"akasha":{"command":"akasha","args":["mcp","--agent-id","claude","--api-key","`+key+`"]}}}`)
	if err := vlt.RevokeAgentKey(keyID); err != nil {
		t.Fatal(err)
	}

	if _, err := ResyncClient(vlt, "akasha", "claude", false); err == nil {
		t.Error("re-admitting a revoked key must fail")
	}
}

func TestAkashaArgsFromTOML(t *testing.T) {
	toml := `model = "gpt"

[mcp_servers.akasha]
command = "akasha"
args = ["mcp", "--agent-id", "codex", "--api-key", "agt_x"]

[mcp_servers.other]
command = "y"
`
	args, ok := akashaArgsFromTOML(toml)
	if !ok {
		t.Fatal("expected akasha block found")
	}
	id, key, _ := agentIDAndKey(args)
	if id != "codex" || key != "agt_x" {
		t.Errorf("got id=%q key=%q", id, key)
	}
	// No akasha block → not found.
	if _, ok := akashaArgsFromTOML(`[mcp_servers.other]`); ok {
		t.Error("expected akasha block absent")
	}
}
