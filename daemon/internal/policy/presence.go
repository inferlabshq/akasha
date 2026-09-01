package policy

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Human presence: making an `ask` something a background process cannot answer.
//
// You cannot establish the identity of a same-UID peer — docs/design/
// same-user-identity.md states that as a theorem, and every rung of the
// identity ladder it lists either has no Linux analogue or attests the calling
// BINARY, which does not stop a rogue script from invoking the real akasha.
//
// So this does not try to identify anyone. It changes what the *authority* is:
// something a background process physically cannot produce. That sidesteps the
// theorem instead of arguing with it, and it is the one same-user answer in that
// design note which needs no per-agent isolation.
//
// A plain dialog is already a presence signal — a rogue process cannot vend
// silently, because a window appears. But a dialog is UI, and a same-uid process
// can drive UI automation, so a button press converts silent theft into noisy
// theft rather than preventing it. A passphrase cannot be produced by a process
// that never had it, no matter what it can read: it is not stored anywhere in
// recoverable form, and it is not the vault key.
//
// touch-id is deliberately NOT accepted yet. It needs LocalAuthentication,
// which means cgo or a second signed helper binary, and the release pipeline
// cross-compiles darwin from Linux with CGO_ENABLED=0. Accepting the value and
// silently falling back to a click would be a policy that reports a protection
// it is not applying, so it is refused at parse instead.
const (
	// AskClick is the default: a dialog with a button.
	AskClick = "click"
	// AskPassphrase additionally requires the approval passphrase.
	AskPassphrase = "passphrase"
)

// PassphraseVerifier checks the human's approval passphrase.
//
// An interface for the same reason StateStore is one: the storage lives in the
// vault, and this package must not depend on it. The daemon supplies the
// implementation at startup.
type PassphraseVerifier interface {
	// VerifyApprovalPassphrase reports whether p matches, and whether one has
	// been set at all. A verifier that has no passphrase configured returns
	// (false, false) so the caller can tell "wrong" from "never set" — they
	// need different messages, and only one of them is the user's mistake.
	VerifyApprovalPassphrase(p []byte) (ok bool, configured bool)
}

// passphrasePrompter is an optional Approver capability: asking the human for a
// secret rather than a button press. An approver that cannot do it makes an
// `ask_requires: passphrase` policy fail CLOSED — see Engine.presenceApprove.
type passphrasePrompter interface {
	PromptPassphrase(req Request, timeout time.Duration) ([]byte, bool)
}

// SetPassphraseVerifier supplies the store that checks approval passphrases.
// Without one, `ask_requires: passphrase` denies rather than degrading to a
// click: a policy asking for a factor the daemon cannot check has not been
// satisfied, and quietly accepting less is how a control stops applying.
func (e *Engine) SetPassphraseVerifier(v PassphraseVerifier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.verifier = v
}

// presenceApprove runs an `ask` at the strength the policy asked for.
//
// Every failure path here returns false. This is the one place in the engine
// where "we could not check" and "the human said no" have the same outcome by
// design — an approval that was not obtained is not an approval.
func (e *Engine) presenceApprove(req Request, requires string, timeout time.Duration) (bool, string) {
	e.mu.Lock()
	ap, v := e.approver, e.verifier
	e.mu.Unlock()
	if ap == nil {
		return false, "no way to ask a human on this machine"
	}

	// Serialised like every other approval: two dialogs racing for one human is
	// how a person clicks Allow on the prompt they were not reading.
	e.askMu.Lock()
	defer e.askMu.Unlock()

	if requires != AskPassphrase {
		return ap.Approve(req, timeout), ""
	}

	prompter, ok := ap.(passphrasePrompter)
	if !ok {
		return false, "this machine's approval dialog cannot ask for a passphrase"
	}
	if v == nil {
		return false, "no approval passphrase is configured (set one with `akasha policy passphrase`)"
	}

	pass, got := prompter.PromptPassphrase(req, timeout)
	defer zero(pass)
	if !got {
		return false, ""
	}
	ok, configured := v.VerifyApprovalPassphrase(pass)
	switch {
	case !configured:
		return false, "no approval passphrase is configured (set one with `akasha policy passphrase`)"
	case !ok:
		return false, "the approval passphrase did not match"
	}
	return true, ""
}

// zero wipes a passphrase buffer. Best-effort — Go may have copied it — but the
// copy this function controls does not outlive the check.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConstantTimeMatch compares a derived key against the stored one without
// leaking the position of the first difference through timing.
func ConstantTimeMatch(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// validAskRequires checks the document-level strength setting.
func validAskRequires(s string) error {
	switch s {
	case "", AskClick, AskPassphrase:
		return nil
	case "touch-id":
		return fmt.Errorf("ask_requires: touch-id is not available in this build "+
			"(it needs LocalAuthentication, and the released binaries are built without cgo). "+
			"Use %q, which works on both platforms", AskPassphrase)
	default:
		return fmt.Errorf("ask_requires must be %q or %q, got %q", AskClick, AskPassphrase, s)
	}
}
