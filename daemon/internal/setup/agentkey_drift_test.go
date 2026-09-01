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
		target := c.envTargetFor()
		if target == nil {
			continue // this harness has no env-injection mechanism yet
		}
		checked++
		p := filepath.Clean(expand(target.path))
		if !masked[p] {
			t.Errorf("setup writes the agent key into %s (%s), but the sandbox does not mask it.\n"+
				"An agent inside `akasha run` can read the key from there and use it against the\n"+
				"daemon with no run capability profile applied. Add it to AgentKeyFiles in\n"+
				"internal/sandbox/agentkey.go.", p, c.label)
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
		if target := c.envTargetFor(); target != nil {
			written[filepath.Clean(expand(target.path))] = true
		}
	}
	for _, p := range sandbox.AgentKeyPathsFor(home, runtime.GOOS) {
		if !written[filepath.Clean(p)] {
			t.Errorf("the sandbox masks %s as an agent-key file, but no harness writes the key there", p)
		}
	}
}
