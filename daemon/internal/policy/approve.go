package policy

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// platformApprover returns the best interactive approver for this OS.
// macOS gets a native dialog (the daemon runs as a launchd user agent, so it
// can present UI in the login session). Everywhere else there is no
// interactive channel yet, so "ask" fails closed to deny — documented in
// docs/POLICY.md.
func platformApprover() Approver {
	if runtime.GOOS == "darwin" {
		return &dialogApprover{}
	}
	return nil
}

// dialogApprover shows a native macOS dialog via osascript and waits for an
// explicit Allow. Everything else — Deny, timeout ("gave up"), osascript
// failure, headless session — is a deny.
type dialogApprover struct{}

func (d *dialogApprover) Approve(req Request, timeout time.Duration) bool {
	lines := []string{"Akasha: approval required", ""}
	if req.AgentID != "" {
		lines = append(lines, fmt.Sprintf("Agent: %s", req.AgentID))
	}
	what := req.Category
	if req.Provider != "" {
		what = req.Provider
		if req.Instance != "" {
			what += ":" + req.Instance
		}
	}
	lines = append(lines, fmt.Sprintf("Operation: %s %s", req.Action, what))
	if req.Risk != "" {
		lines = append(lines, fmt.Sprintf("Risk: %s", req.Risk))
	}
	if req.Tool != "" {
		lines = append(lines, fmt.Sprintf("Tool: %s", req.Tool))
	}
	if req.Task != "" {
		lines = append(lines, fmt.Sprintf("Task: %s", truncate(req.Task, 200)))
	}
	text := strings.Join(lines, "\n")

	script := fmt.Sprintf(
		`display dialog %s buttons {"Deny", "Allow"} default button "Deny" with icon caution giving up after %d`,
		appleScriptQuote(text), int(timeout.Seconds()))

	// Give osascript slightly longer than the dialog's own timeout, then kill
	// it — a wedged UI session must still resolve to deny.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).Output()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "button returned:Allow") && !strings.Contains(s, "gave up:true")
}

// appleScriptQuote renders a string literal for AppleScript: backslashes and
// double quotes escaped, newlines become literal \n escapes AppleScript
// understands inside quoted text via "\n".
func appleScriptQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
