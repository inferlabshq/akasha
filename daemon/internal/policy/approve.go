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

// Field caps. Every interpolated value is bounded, not just Task: an unbounded
// Tool or AgentID could make the dialog taller than the screen and push the
// Deny/Allow buttons out of view.
const (
	maxFieldLen = 80
	maxTaskLen  = 200
)

func (d *dialogApprover) Approve(req Request, timeout time.Duration) bool {
	// Server-derived facts FIRST, caller-supplied text last and clearly marked.
	//
	// Every value here used to be interpolated as `Label: value` with nothing a
	// value could not itself contain, and appleScriptQuote turned a newline into
	// a real line break in the rendered dialog. So a caller could write
	// "sync\nRisk: low\nTool: akasha_helper" into `task` — or, worse, into
	// `requesting_tool`, which rendered ABOVE task — and forge lines that read
	// exactly like the daemon's own. The human then approved on the strength of
	// text written by the thing being gated.
	//
	// Two changes make that impossible: control characters are stripped from
	// every value (see dialogSafe), and the facts the daemon establishes are
	// printed before anything the caller controls, under a heading that says so.
	what := req.Category
	if req.Provider != "" {
		what = req.Provider
		if req.Instance != "" {
			what += ":" + req.Instance
		}
	}

	lines := []string{"Akasha: approval required", ""}
	lines = append(lines, fmt.Sprintf("Operation: %s %s",
		dialogSafe(req.Action, maxFieldLen), dialogSafe(what, maxFieldLen)))
	if req.Risk != "" {
		lines = append(lines, fmt.Sprintf("Risk: %s", dialogSafe(req.Risk, maxFieldLen)))
	}
	if req.Token != "" {
		// Name the actual secret. Two simultaneous prompts were otherwise
		// indistinguishable — "retrieve Credential" twice, one benign.
		lines = append(lines, fmt.Sprintf("Secret: %s", dialogSafe(req.Token, maxFieldLen)))
	}

	claimed := []string{}
	if req.AgentID != "" {
		claimed = append(claimed, fmt.Sprintf("  Agent: %s", dialogSafe(req.AgentID, maxFieldLen)))
	}
	if req.Tool != "" {
		claimed = append(claimed, fmt.Sprintf("  Tool: %s", dialogSafe(req.Tool, maxFieldLen)))
	}
	if req.Task != "" {
		claimed = append(claimed, fmt.Sprintf("  Task: %s", dialogSafe(req.Task, maxTaskLen)))
	}
	if len(claimed) > 0 {
		lines = append(lines, "", "Reported by the caller (unverified):")
		lines = append(lines, claimed...)
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

// dialogSafe prepares one caller-supplied value for display: control characters
// become spaces, and the result is capped.
//
// The escaping this replaces was the vulnerability. appleScriptQuote mapped a
// newline to the AppleScript escape `\n`, which AppleScript then renders as a
// REAL line break — so escaping preserved the attacker's layout rather than
// neutralising it, and a value could forge whole lines of the dialog. Carriage
// return was not handled at all, and renders as a line break too.
//
// Stripping rather than escaping is the fix: a value can no longer produce a
// line break by any route, so it cannot impersonate a label the daemon prints.
func dialogSafe(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// Other C0 controls: drop entirely.
		default:
			b.WriteRune(r)
		}
	}
	return truncate(strings.TrimSpace(b.String()), max)
}

// appleScriptQuote renders a string literal for AppleScript: backslashes and
// double quotes escaped. Callers must pass values through dialogSafe first —
// this function deliberately no longer does anything with newlines, because
// every value reaching it should already be free of them.
func appleScriptQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// truncate cuts s to n RUNES, not bytes. Slicing bytes could split a multi-byte
// character and emit invalid UTF-8, which osascript then rejects — turning a
// long task description into a failed dialog, i.e. a deny.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
