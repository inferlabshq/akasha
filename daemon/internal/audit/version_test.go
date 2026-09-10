package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every audit line carries the build that wrote it. Without it a reviewer
// reading a log across an upgrade cannot tell which behaviour produced a line.
func TestEveryEventCarriesTheWritersBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Emit(Event{Action: ActionInspected, AgentID: "a"})
	l.Close()
	data, _ := os.ReadFile(path)
	line := strings.TrimSpace(string(data))
	var e map[string]interface{}
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("not JSON: %s", line)
	}
	if v, _ := e["akasha_version"].(string); v == "" {
		t.Errorf("line has no akasha_version: %s", line)
	}
}
