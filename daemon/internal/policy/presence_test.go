package policy

import (
	"os"
	"strings"
	"testing"
	"time"
)

// clickOnly approves on a button and cannot ask for a secret — the shape of an
// approver on a machine whose dialog program has no password mode.
type clickOnly struct{ called int }

func (c *clickOnly) Approve(Request, time.Duration) bool { c.called++; return true }

// prompter answers with a fixed passphrase.
type prompter struct {
	clickOnly
	give   string
	refuse bool
}

func (p *prompter) PromptPassphrase(Request, time.Duration) ([]byte, bool) {
	if p.refuse {
		return nil, false
	}
	return []byte(p.give), true
}

// verifier accepts exactly one passphrase.
type verifier struct {
	want       string
	configured bool
}

func (v verifier) VerifyApprovalPassphrase(p []byte) (bool, bool) {
	if !v.configured {
		return false, false
	}
	return string(p) == v.want, true
}

func engineWith(t *testing.T, doc string, ap Approver, v PassphraseVerifier) (*Engine, *Policy) {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(path)
	e.SetApprover(ap)
	if v != nil {
		e.SetPassphraseVerifier(v)
	}
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}

const askDoc = `
ask_requires: passphrase
rules:
  - action: broker
    effect: ask
    reason: production needs a human
`

// The point of the feature: a correct passphrase approves.
func TestPassphraseApprovalAllows(t *testing.T) {
	e, _ := engineWith(t, askDoc, &prompter{give: "correct horse"}, verifier{want: "correct horse", configured: true})
	if err := e.Authorize(Request{Action: "broker", provider: "aws"}); err != nil {
		t.Fatalf("a correct passphrase was refused: %v", err)
	}
}

// …and a wrong one does not, with a message that says which mistake it was.
func TestWrongPassphraseDenies(t *testing.T) {
	e, _ := engineWith(t, askDoc, &prompter{give: "wrong"}, verifier{want: "right", configured: true})
	err := e.Authorize(Request{Action: "broker", provider: "aws"})
	if err == nil {
		t.Fatal("a wrong passphrase was accepted")
	}
	if !strings.Contains(err.Error(), "did not match") {
		t.Errorf("the denial should say the passphrase was wrong, got: %v", err)
	}
}

// The failure that matters most: a policy demanding a factor the machine cannot
// check must DENY, never quietly fall back to a button. A control that silently
// downgrades is one you stop being able to reason about.
func TestPassphraseRequiredButUncheckableFailsClosed(t *testing.T) {
	t.Run("approver cannot prompt", func(t *testing.T) {
		click := &clickOnly{}
		e, _ := engineWith(t, askDoc, click, verifier{want: "x", configured: true})
		err := e.Authorize(Request{Action: "broker", provider: "aws"})
		if err == nil {
			t.Fatal("allowed with an approver that cannot ask for a passphrase")
		}
		if click.called != 0 {
			t.Error("it fell back to the click dialog, which is the downgrade this must not do")
		}
		if !strings.Contains(err.Error(), "cannot ask for a passphrase") {
			t.Errorf("the denial should name the cause, got: %v", err)
		}
	})

	t.Run("no passphrase configured", func(t *testing.T) {
		e, _ := engineWith(t, askDoc, &prompter{give: "anything"}, verifier{configured: false})
		err := e.Authorize(Request{Action: "broker", provider: "aws"})
		if err == nil {
			t.Fatal("allowed with no approval passphrase configured")
		}
		if !strings.Contains(err.Error(), "akasha policy passphrase") {
			t.Errorf("the denial should name the fix, got: %v", err)
		}
	})

	t.Run("no verifier wired at all", func(t *testing.T) {
		e, _ := engineWith(t, askDoc, &prompter{give: "anything"}, nil)
		if err := e.Authorize(Request{Action: "broker", provider: "aws"}); err == nil {
			t.Fatal("allowed with no verifier — the daemon could not have checked anything")
		}
	})
}

// A human dismissing the prompt is a decision, not a malfunction, and must not
// be dressed up as one.
func TestRefusedPromptIsAPlainDeny(t *testing.T) {
	e, _ := engineWith(t, askDoc, &prompter{refuse: true}, verifier{want: "x", configured: true})
	err := e.Authorize(Request{Action: "broker", provider: "aws"})
	if err == nil {
		t.Fatal("a dismissed prompt allowed the operation")
	}
	for _, wrong := range []string{"cannot", "not configured"} {
		if strings.Contains(err.Error(), wrong) {
			t.Errorf("a human refusal was reported as a malfunction: %v", err)
		}
	}
}

// The default is unchanged: no ask_requires means a button, exactly as before.
func TestDefaultAskIsStillAClick(t *testing.T) {
	click := &clickOnly{}
	e, p := engineWith(t, "rules: [{action: broker, effect: ask}]\n", click, nil)
	if p.AskRequires != AskClick {
		t.Errorf("AskRequires defaulted to %q, want %q", p.AskRequires, AskClick)
	}
	if err := e.Authorize(Request{Action: "broker"}); err != nil {
		t.Fatalf("a plain ask stopped working: %v", err)
	}
	if click.called != 1 {
		t.Errorf("the click dialog was shown %d times, want 1", click.called)
	}
}

// touch-id must be refused rather than accepted-and-ignored. Accepting it would
// give a policy file that reports a protection the daemon is not applying.
func TestTouchIDIsRefusedNotSilentlyDowngraded(t *testing.T) {
	_, err := Parse([]byte("ask_requires: touch-id\nrules: []\n"))
	if err == nil {
		t.Fatal("touch-id was accepted; the policy would claim a factor that is not applied")
	}
	for _, want := range []string{"not available", "passphrase"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should explain and offer the alternative, got: %v", err)
		}
	}
}

func TestUnknownAskRequiresIsRefused(t *testing.T) {
	if _, err := Parse([]byte("ask_requires: vibes\nrules: []\n")); err == nil {
		t.Fatal("an unknown ask_requires value was accepted")
	}
}
