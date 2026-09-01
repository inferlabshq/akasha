package vault

import "testing"

func TestApprovalPassphraseRoundTrip(t *testing.T) {
	v := openTestVault(t)

	// Nothing set: "wrong" and "never configured" must be distinguishable, or a
	// user on a fresh machine is told they typed it incorrectly.
	if ok, configured := v.VerifyApprovalPassphrase([]byte("anything")); ok || configured {
		t.Fatalf("unset vault reported ok=%v configured=%v, want false/false", ok, configured)
	}
	if v.HasApprovalPassphrase() {
		t.Fatal("HasApprovalPassphrase is true before one is set")
	}

	if err := v.SetApprovalPassphrase([]byte("correct horse battery staple")); err != nil {
		t.Fatal(err)
	}
	if !v.HasApprovalPassphrase() {
		t.Error("HasApprovalPassphrase is false after setting one")
	}
	if ok, configured := v.VerifyApprovalPassphrase([]byte("correct horse battery staple")); !ok || !configured {
		t.Errorf("the correct passphrase did not verify: ok=%v configured=%v", ok, configured)
	}
	if ok, configured := v.VerifyApprovalPassphrase([]byte("correct horse battery stapl")); ok || !configured {
		t.Errorf("a near-miss verified: ok=%v configured=%v", ok, configured)
	}

	// Replacing it invalidates the old one, or rotating would be theatre.
	if err := v.SetApprovalPassphrase([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := v.VerifyApprovalPassphrase([]byte("correct horse battery staple")); ok {
		t.Error("the previous passphrase still verifies after being replaced")
	}
	if ok, _ := v.VerifyApprovalPassphrase([]byte("second")); !ok {
		t.Error("the new passphrase does not verify")
	}

	// Clearing returns to "not configured" — which makes an
	// `ask_requires: passphrase` policy DENY, not fall back to a button.
	if err := v.ClearApprovalPassphrase(); err != nil {
		t.Fatal(err)
	}
	if ok, configured := v.VerifyApprovalPassphrase([]byte("second")); ok || configured {
		t.Errorf("after clearing: ok=%v configured=%v, want false/false", ok, configured)
	}
}

// It is stored as a verifier, not as the passphrase. Someone who reads the
// metadata row must not thereby learn the secret.
func TestApprovalPassphraseIsNotStoredInTheClear(t *testing.T) {
	v := openTestVault(t)
	const pass = "a-distinctive-passphrase-value"
	if err := v.SetApprovalPassphrase([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{approvalSaltKey, approvalVerifierKey} {
		got, err := v.getMetadata(key)
		if err != nil {
			t.Fatal(err)
		}
		if got == "" {
			t.Errorf("%s is empty", key)
		}
		if got == pass {
			t.Errorf("%s holds the passphrase verbatim", key)
		}
	}
}

// An empty passphrase is a factor anything can produce.
func TestEmptyApprovalPassphraseIsRefused(t *testing.T) {
	v := openTestVault(t)
	if err := v.SetApprovalPassphrase(nil); err == nil {
		t.Fatal("an empty approval passphrase was accepted")
	}
	if v.HasApprovalPassphrase() {
		t.Error("the refused empty passphrase was stored anyway")
	}
}
