package main

import "testing"

// `akasha setup` no longer writes --api-key, so the MCP server has to find its
// key in the environment or it authenticates as nobody and every vault tool
// answers 401. The flag is still honoured for configs written before the move.
func TestMCPKeyPrefersTheFlagAndFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv("AKASHA_AGENT_KEY", "agt_from_env")

	if got := mcpKey(""); got != "agt_from_env" {
		t.Errorf("with no flag, the key must come from the environment; got %q", got)
	}
	if got := mcpKey("agt_from_flag"); got != "agt_from_flag" {
		t.Errorf("an explicit --api-key must win over ambient env; got %q", got)
	}

	t.Setenv("AKASHA_AGENT_KEY", "")
	if got := mcpKey(""); got != "" {
		t.Errorf("no flag and no env must yield no key, not a guess; got %q", got)
	}
}
