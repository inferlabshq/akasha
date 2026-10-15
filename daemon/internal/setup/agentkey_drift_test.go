package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/sandbox"
)

// Every file setup writes AKASHA_AGENT_KEY into must be masked inside a run.
//
// This is a DRIFT test, and drift is the whole risk. The bypass it guards
// against was not a design mistake — the sandbox masked ~/.aws, ~/.ssh and
// ~/.akasha correctly — it was one file, akasha's own, on a list maintained by
// hand in a different package from the code that creates it. An agent inside
// `akasha run --assume aws:default` read the persistent key out of
// ~/.claude/settings.json and resolved aws:prod with it, a profile the run was
// never granted.
//
// So: add a harness to envTargetFor and this fails until the sandbox knows
// about it too. The failure is the point.
//
// It used to check only envTargetFor's settings files. The MCP config each
// client gets — ~/.claude.json, ~/.cursor/mcp.json, VS Code's mcp.json — has
// carried the key in its server "env" block since the key moved out of argv,
// and none of them was masked: an agent in a default-network run could read
// it from ~/.claude.json and use it over the loopback port. Both are key
// files, so both are checked.
func TestSandboxMasksEveryFileTheAgentKeyIsWrittenTo(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to resolve paths against")
	}

	masked := map[string]bool{}
	for _, p := range sandbox.AgentKeyPathsFor(home, runtime.GOOS) {
		masked[filepath.Clean(p)] = true
	}

	checked := 0
	for _, c := range mcpClients {
		for _, p := range keyFilesFor(c) {
			checked++
			if !masked[p] {
				t.Errorf("setup writes the agent key into %s (%s), but the sandbox does not mask it.\n"+
					"An agent inside `akasha run` can read the key from there and use it against the\n"+
					"daemon with no run capability profile applied. Add it to AgentKeyFiles in\n"+
					"internal/sandbox/agentkey.go.", p, c.label)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no harness reported an env target — this test would pass without checking anything")
	}
}

// The reverse direction, so the mask list does not rot into paths nothing
// writes to: every masked path must be one of the platform's real targets.
// A stale entry is harmless to security but it is a lie in a file whose whole
// value is that a reader can trust it.
func TestMaskedAgentKeyFilesAreOnesSetupActuallyWritesTo(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to resolve paths against")
	}
	written := map[string]bool{}
	for _, c := range mcpClients {
		for _, p := range keyFilesFor(c) {
			written[p] = true
		}
	}
	for _, p := range sandbox.AgentKeyPathsFor(home, runtime.GOOS) {
		if !written[filepath.Clean(p)] {
			t.Errorf("the sandbox masks %s as an agent-key file, but no harness writes the key there", p)
		}
	}
}

// keyFilesFor is every file setup writes this client's agent key into: its MCP
// config (the server's env block) and, where it has one, its env-injection
// settings file.
func keyFilesFor(c mcpClient) []string {
	out := []string{filepath.Clean(expand(c.cfgPath))}
	if target := c.envTargetFor(); target != nil {
		out = append(out, filepath.Clean(expand(target.path)))
	}
	return out
}
