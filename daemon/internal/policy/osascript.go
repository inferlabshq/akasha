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

// PromptPassphrase asks for the approval passphrase instead of a button press.
//
// The script returns ONLY the passphrase, never the button. osascript's default
// rendering of a dialog result is "button returned:Approve, text returned:hunter2",
// and parsing the secret back out of that is a trap: a passphrase containing the
// literal ", text returned:" would split wrong. Deciding inside AppleScript and
// returning one value removes the parse entirely — an empty result is a refusal,
// whether the human denied, gave up, or entered nothing.
//
// The passphrase reaches us on the subprocess's STDOUT, never argv. argv is
// readable through /proc by any same-uid process, which is the exact adversary
// this feature exists for; putting the secret there would defeat it.
func (d *dialogApprover) PromptPassphrase(req Request, timeout time.Duration) ([]byte, bool) {
	script := strings.Join([]string{
		`set r to display dialog ` + appleScriptQuote(passphraseText(req)) +
			` default answer "" with hidden answer with icon caution` +
			` buttons {"Deny", "Approve"} default button "Deny" giving up after ` +
			fmt.Sprint(int(timeout.Seconds())),
		`if gave up of r then return ""`,
		`if button returned of r is not "Approve" then return ""`,
		`return text returned of r`,
	}, "\n")

	ctx, cancel := context.WithTimeout(context.Background(), timeout+dialogKillGrace)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).Output()
	if err != nil {
		return nil, false
	}
	pass := []byte(strings.TrimRight(string(out), "\r\n"))
	if len(pass) == 0 {
		return nil, false
	}
	return pass, true
}

// passphraseText is the approval body with a line saying why a passphrase is
// being asked for. Without it the prompt looks like a credential harvest, which
// is precisely the thing a user should be suspicious of.
func passphraseText(req Request) string {
	return approvalText(req) + "\n\nEnter your Akasha approval passphrase to allow this." +
		"\nThis is not your login password, and no agent can produce it."
}
