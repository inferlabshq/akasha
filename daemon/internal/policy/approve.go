package policy

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// Interactive approval: the dispatch site and everything both backends share.
// The backends themselves live one per mechanism — osascript.go (macOS),
// zenity.go (Linux) — mirroring internal/sandbox's sbpl.go / bwrap.go split.
//
// Platform selection is a runtime.GOOS switch rather than _darwin.go / _linux.go
// build tags, for the reason spelled out in internal/sandbox/dispatch.go: both
// backends are os/exec plus string building, with no platform-only symbols to
// make compile, and CI runs on Linux — under build tags the osascript path,
// which is the one carrying a generated-code surface, would never be compiled or
// tested there. Every test in this package exercises both backends on whichever
// OS it runs. Introduce a tag when an import forces one, not preemptively.

// platformApprover returns the best interactive approver for this OS.
//
//   - macOS: a native dialog via osascript. The daemon runs as a launchd user
//     agent, so it can present UI in the login session.
//   - Linux: a zenity dialog. The systemd user unit reaches the desktop through
//     the same `systemctl --user import-environment` the session already
//     performs to hand the daemon DBUS_SESSION_BUS_ADDRESS — without which the
//     vault's Secret Service keyring would not work either, so a Linux machine
//     running a vault at all is one where this can work.
//   - Anything else: nil, so "ask" fails closed to deny — documented in
//     docs/POLICY.md.
func platformApprover() Approver {
	switch runtime.GOOS {
	case "darwin":
		return &dialogApprover{}
	case "linux":
		return &linuxDialogApprover{}
	}
	return nil
}

// unavailableApprover is an optional capability an Approver may implement.
//
// An approver can exist and still have no way to reach a human right now — no
// graphical session, no dialog program installed — and that is a different
// fact from "the human said no". Authorize reports the reason so the denial
// names its own fix instead of implying a decision nobody made.
type unavailableApprover interface {
	// Unavailable returns why this approver cannot prompt, or "" if it can.
	Unavailable() string
}

// ApprovalChannel reports whether this machine can actually prompt a human for
// an "ask" decision: "" if it can, otherwise why it cannot.
//
// Exported so `akasha policy validate` can tell someone that their `ask` rules
// are silently behaving as `deny`. A control that is off is only safe if you
// know it is off, and the alternative is discovering it when a gated operation
// fails for a reason that reads like a refusal.
func ApprovalChannel() string {
	a := platformApprover()
	if a == nil {
		return "no interactive approval channel on " + runtime.GOOS
	}
	if u, ok := a.(unavailableApprover); ok {
		return u.Unavailable()
	}
	return ""
}

// Field caps. Every interpolated value is bounded, not just Task: an unbounded
// Tool or AgentID could make the dialog taller than the screen and push the
// Deny/Allow buttons out of view.
const (
	maxFieldLen = 80
	maxTaskLen  = 200
)

// dialogKillGrace is how much longer than the dialog's own timeout the helper
// process is allowed to live before it is killed. A wedged UI session must
// still resolve to deny. A var so tests need not wait it out.
var dialogKillGrace = 10 * time.Second

// approvalText renders the dialog body. Shared by every backend: the wording of
// a security prompt is not something to let drift per OS. A backend adapts this
// to its own renderer (see zenityText) but never rewrites it.
//
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
func approvalText(req Request) string {
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
	return strings.Join(lines, "\n")
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
