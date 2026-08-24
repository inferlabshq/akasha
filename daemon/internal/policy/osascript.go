package policy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// dialogApprover shows a native macOS dialog via osascript and waits for an
// explicit Allow. Everything else — Deny, timeout ("gave up"), osascript
// failure, headless session — is a deny.
type dialogApprover struct{}

func (d *dialogApprover) Approve(req Request, timeout time.Duration) bool {
	script := fmt.Sprintf(
		`display dialog %s buttons {"Deny", "Allow"} default button "Deny" with icon caution giving up after %d`,
		appleScriptQuote(approvalText(req)), int(timeout.Seconds()))

	// Give osascript slightly longer than the dialog's own timeout, then kill
	// it — a wedged UI session must still resolve to deny.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+dialogKillGrace)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).Output()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "button returned:Allow") && !strings.Contains(s, "gave up:true")
}

// appleScriptQuote renders a string literal for AppleScript: backslashes and
// double quotes escaped. Callers must pass values through dialogSafe first —
// this function deliberately no longer does anything with newlines, because
// every value reaching it should already be free of them.
func appleScriptQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
