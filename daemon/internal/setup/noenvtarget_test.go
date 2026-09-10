package setup

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A client with no env target used to get MCP tools, a key, "Restart Windsurf",
// and silence about the fact that environment ownership -- the one intervention
// measured to change agent behaviour -- was not wired for it. Provider tooling
// in that client's terminal did not route through akasha, and nothing said so.
func TestClientsWithoutAnEnvTargetAreToldWhatTheyDidNotGet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	orig := mcpClients
	t.Cleanup(func() { mcpClients = orig })
	mcpClients = []mcpClient{{id: "windsurf", label: "Windsurf", dir: dir,
		cfgPath: filepath.Join(dir, "mcp_config.json"), format: "json"}}

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	configureMCPClients(setupVault{fakeVault: &fakeVault{}}, "akasha", []string{"windsurf"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "NOT") || !strings.Contains(out, "export AKASHA_AGENT_ID=") {
		t.Errorf("windsurf was not told its sessions are unrouted, or not given the exports:\n%s", out)
	}
	if strings.Contains(out, "Session env routed through akasha") {
		t.Error("claimed env ownership for a client that has no env target")
	}
}
