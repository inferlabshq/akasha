package vault

import (
	"encoding/base64"
	"fmt"

	vaultcrypto "github.com/inferlabshq/akasha/daemon/internal/crypto"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
)

// The approval passphrase: a human-presence factor for policy `ask` rules.
//
// It is NOT a second encryption factor, and deliberately not the vault
// passphrase. The vault passphrase is combined into the encryption key at open
// time, is optional, and is never stored in any recoverable form — there is
// nothing to check a single entry against without re-deriving the whole key.
// More to the point, the job here is different: this exists to be something a
// background process cannot produce, not something that decrypts anything. If
// this value leaked it would grant no access to any secret; it would only let
// the holder answer a prompt.
//
// Stored as Argon2id output over a per-install salt, so the metadata row is not
// the passphrase and an offline guess costs a full derivation each time.
const (
	approvalSaltKey     = "approval_salt"
	approvalVerifierKey = "approval_verifier"
)

// SetApprovalPassphrase stores the verifier for p, replacing any existing one.
func (v *Vault) SetApprovalPassphrase(p []byte) error {
	if len(p) == 0 {
		return fmt.Errorf("approval passphrase cannot be empty")
	}
	salt, err := vaultcrypto.NewArgon2Salt()
	if err != nil {
		return err
	}
	derived := vaultcrypto.DerivePassphraseKey(p, salt, vaultcrypto.DefaultArgon2Params)
	if err := v.setMetadata(approvalSaltKey, base64.StdEncoding.EncodeToString(salt)); err != nil {
		return err
	}
	// The verifier is written LAST. A crash between the two writes then leaves a
	// salt with no verifier, which reads as "not configured" — and an `ask`
	// requiring a passphrase fails closed. The other order would leave a stale
	// verifier against a fresh salt, which no passphrase could ever satisfy and
	// which nothing would explain.
	return v.setMetadata(approvalVerifierKey, base64.StdEncoding.EncodeToString(derived))
}

// ClearApprovalPassphrase removes it. An `ask_requires: passphrase` policy then
// denies rather than falling back to a click — see policy.presenceApprove.
func (v *Vault) ClearApprovalPassphrase() error {
	if err := v.setMetadata(approvalVerifierKey, ""); err != nil {
		return err
	}
	return v.setMetadata(approvalSaltKey, "")
}

// HasApprovalPassphrase reports whether one is set, without checking a value.
func (v *Vault) HasApprovalPassphrase() bool {
	_, _, ok := v.approvalVerifier()
	return ok
}

func (v *Vault) approvalVerifier() (salt, derived []byte, ok bool) {
	se, err := v.getMetadata(approvalSaltKey)
	if err != nil || se == "" {
		return nil, nil, false
	}
	de, err := v.getMetadata(approvalVerifierKey)
	if err != nil || de == "" {
		return nil, nil, false
	}
	salt, err = base64.StdEncoding.DecodeString(se)
	if err != nil {
		return nil, nil, false
	}
	derived, err = base64.StdEncoding.DecodeString(de)
	if err != nil || len(derived) == 0 {
		return nil, nil, false
	}
	return salt, derived, true
}

// VerifyApprovalPassphrase implements policy.PassphraseVerifier.
//
// Returns (false, false) when none is configured, so the caller can tell "that
// was wrong" from "there is nothing to check against" — one of those is the
// user's mistake and the other is a machine that was never set up, and telling
// someone the wrong one costs them an afternoon.
func (v *Vault) VerifyApprovalPassphrase(p []byte) (ok bool, configured bool) {
	salt, want, have := v.approvalVerifier()
	if !have {
		return false, false
	}
	got := vaultcrypto.DerivePassphraseKey(p, salt, vaultcrypto.DefaultArgon2Params)
	return policy.ConstantTimeMatch(got, want), true
}
