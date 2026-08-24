package policy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// linuxDialogApprover shows a zenity dialog and waits for an explicit Allow.
// Everything else — Deny, Escape, the dialog's timeout, a zenity that will not
// start, no graphical session — is a deny.
//
// zenity only, deliberately. kdialog is the obvious second backend and is left
// out because it cannot express this control's guarantees: `kdialog --yesno`
// has no default-no option, and its exit code 1 means BOTH "No" and "dismissed
// with Escape". So the label swap that would restore a default-deny button
// also turns Escape — the likeliest way someone dismisses a prompt they did
// not expect — into Allow. A backend that fails open on Escape is worse than
// no backend, and one that quietly defaults to Allow weakens a property
// POLICY.md states for every platform. zenity gives default-deny, a real
// timeout and unambiguous exit codes, and installs fine under KDE.
type linuxDialogApprover struct{}

// zenityPaths is a fixed candidate list, never PATH: this program decides
// whether a gated operation proceeds, so a PATH directory any local process can
// write must not get to choose what asks the question. Same rule as the service
// tools in internal/setup and the backend binaries in internal/sandbox. A var
// so tests can point it at a stub.
var zenityPaths = []string{
	"/usr/bin/zenity",
	"/bin/zenity",
	"/usr/local/bin/zenity",
	"/run/current-system/sw/bin/zenity", // NixOS
}

func (l *linuxDialogApprover) Unavailable() string {
	if !hasGraphicalSession() {
		return "no graphical session — neither DISPLAY nor WAYLAND_DISPLAY is set " +
			"in the daemon's environment (try: systemctl --user import-environment " +
			"DISPLAY WAYLAND_DISPLAY XAUTHORITY && systemctl --user restart akasha)"
	}
	if _, ok := firstExecutable(zenityPaths); !ok {
		return "zenity is not installed (Debian/Ubuntu: apt install zenity; " +
			"Fedora: dnf install zenity; Arch: pacman -S zenity)"
	}
	return ""
}

func (l *linuxDialogApprover) Approve(req Request, timeout time.Duration) bool {
	bin, ok := firstExecutable(zenityPaths)
	if !ok || !hasGraphicalSession() {
		return false
	}

	secs := int(timeout.Seconds())
	if secs < 1 {
		// zenity reads --timeout=0 as "no timeout", which would leave the
		// gated operation hanging until the grace kill below. Still closed,
		// but late — keep the dialog's own timeout real.
		secs = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+dialogKillGrace)
	defer cancel()
	// Every argument is one literal argv element. Unlike the macOS side, where
	// the dialog is a generated AppleScript program, there is no quoting layer
	// here to get wrong.
	err := exec.CommandContext(ctx, bin,
		"--question",
		"--title=Akasha",
		"--text="+zenityText(req),
		"--no-markup",
		"--default-cancel",
		"--ok-label=Allow",
		"--cancel-label=Deny",
		fmt.Sprintf("--timeout=%d", secs),
	).Run()

	// Exit 0 is the Allow button and nothing else. 1 is Deny or Escape, 5 is
	// zenity's own timeout, and every other failure — no display, an unknown
	// option on an ancient zenity, killed by the grace timer — is non-nil too.
	// Fail-closed needs no special case: it is the default branch.
	return err == nil
}

// zenityText renders the dialog body for zenity, with the one character that
// could turn caller text into markup removed.
//
// zenity parses --text as Pango markup unless told otherwise, so `<span
// size="0">` would let a value hide itself from the human, and `<b>` would let
// it style itself to look like one of the daemon's own labels — the same
// forgery dialogSafe closes for line breaks, by a different route. --no-markup
// is passed as well; this strip is what holds if a zenity build ignores or
// lacks the flag. No label the daemon prints contains either character, so
// nothing legitimate is lost. An entity like &#60; is left alone on purpose:
// Pango renders it as a literal character, it cannot re-open as a tag.
func zenityText(req Request) string {
	return strings.NewReplacer("<", "", ">", "").Replace(approvalText(req))
}

// hasGraphicalSession reports whether the daemon's environment can reach a
// display server at all. Checked per call rather than once at construction: the
// desktop may import DISPLAY into the systemd user manager after the daemon has
// already started, and re-probing costs two getenvs.
func hasGraphicalSession() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

// firstExecutable returns the first candidate that exists as an executable file.
func firstExecutable(candidates []string) (string, bool) {
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		return p, true
	}
	return "", false
}
