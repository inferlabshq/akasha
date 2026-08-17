// Package identity derives NON-SECRET facts about a vaulted credential —
// which account is this, what kind of key — without disclosing or using it.
//
// This is Akasha's third access mode, and the cheapest one:
//
//	READ     "give me the secret"       → policy-gated, hands over the credential
//	USE      "act with it on my behalf" → brokered, audited
//	DESCRIBE "who is this credential?"  → this package
//
// Before DESCRIBE existed, an agent that only needed an account number had to
// escalate all the way to USE: assume the credential, shell out to the
// provider's CLI, and make a network round-trip — which also meant a credential
// with revoked keys could not answer a question whose answer was sitting in the
// key id the whole time.
//
// # Threat model
//
// A derivation runs close to credential material, so this package is built so
// that a contract CANNOT become a disclosure path, even if a provider template
// is hostile and even if a future contract is written carelessly:
//
//   - Contracts are Go-owned and named. A template selects one by name and
//     supplies nothing else — no command, no field path, no format string.
//   - A contract declares the field names it reads (RequiredFields). The caller
//     is expected to decrypt ONLY those, and to refuse when the template marks
//     one of them secret. A template cannot widen what gets decrypted by
//     renaming or reclassifying fields.
//   - Output may never echo input (enforced in Derive, for every contract).
//     This is the invariant that holds even when the template lies: routing a
//     secret into a contract cannot get it back out, because no contract can
//     return a value it was given.
//   - Output may not carry control characters, so a derived value cannot inject
//     terminal escapes or extra lines into whatever prints it.
//
// Nothing here makes a network call. That is a security property as much as a
// performance one: DESCRIBE cannot be turned into an exfiltration trigger, and
// it keeps answering for credentials that no longer authenticate.
package identity

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Contract names. Each maps to a Go function below; templates may name only
// these.
const (
	// ContractAWSAccessKeyAccountID recovers the 12-digit AWS account number
	// from the access key id, offline.
	ContractAWSAccessKeyAccountID = "aws-access-key-account-id"
)

// Facts is the result of a derivation: non-secret key/value pairs plus a
// plain-language note on how they were obtained, so a caller can tell a locally
// derived fact from a provider-confirmed one.
type Facts struct {
	Contract string            `json:"contract"`
	Values   map[string]string `json:"values"`
	Source   string            `json:"source"`
	// Offline reports that no network call was involved. Offline facts stay
	// available after a credential is deactivated, which is precisely when
	// somebody is trying to work out what it was.
	Offline bool `json:"offline"`
}

// contract is a Go-owned derivation: the credential fields it reads, the facts
// it can compute, and the computation itself.
//
// requires and produces are both declared rather than discovered, because both
// are checked before anything runs: requires bounds what gets decrypted, and
// produces lets a template's disclosure list be validated at load time instead
// of failing at use time.
type contract struct {
	// requires lists credential field names this contract needs. The caller
	// decrypts exactly these and no more.
	requires []string
	// produces lists every fact name this contract can emit. A template may
	// reveal any subset; it may not name a fact that does not exist.
	produces []string
	derive   func(fields map[string]string) (*Facts, error)
}

var contracts = map[string]contract{
	ContractAWSAccessKeyAccountID: {
		// Only the access key id. The secret access key is never named here, so
		// a DESCRIBE never has a reason to decrypt it.
		requires: []string{"access_key_id"},
		produces: []string{"account_id", "key_type"},
		derive:   awsAccountFromAccessKey,
	},
}

// Known reports whether a contract name is implemented. Template validation
// calls this so the allowlist has exactly one source of truth — a template
// naming an unimplemented contract is rejected at load time, not at use time.
func Known(name string) bool {
	_, ok := contracts[name]
	return ok
}

// Names lists the implemented contracts, for help text and error messages.
func Names() []string { return []string{ContractAWSAccessKeyAccountID} }

// RequiredFields returns the credential field names a contract reads. Callers
// use this to decrypt the minimum, and to refuse when the provider template
// declares one of these fields secret — a field a contract reads must be one
// the provider itself considers non-secret.
func RequiredFields(name string) ([]string, error) {
	c, ok := contracts[name]
	if !ok {
		return nil, fmt.Errorf("unknown identity contract %q", name)
	}
	out := make([]string, len(c.requires))
	copy(out, c.requires)
	return out, nil
}

// Produces returns every fact name a contract can emit. Template validation
// checks a template's disclosure list against this, so a template that asks to
// reveal a fact the contract cannot compute fails at load rather than silently
// revealing nothing.
func Produces(name string) ([]string, error) {
	c, ok := contracts[name]
	if !ok {
		return nil, fmt.Errorf("unknown identity contract %q", name)
	}
	out := make([]string, len(c.produces))
	copy(out, c.produces)
	return out, nil
}

// Derive runs a named contract over exactly the fields it requires.
//
// It returns an error rather than partial facts when the credential does not
// carry what the contract needs, so a caller never reports a confidently wrong
// account number.
//
// Derive computes the contract's FULL output. Choosing which of those facts is
// actually disclosed belongs to the template, not here — see Facts.Reveal.
func Derive(name string, fields map[string]string) (*Facts, error) {
	c, ok := contracts[name]
	if !ok {
		return nil, fmt.Errorf("unknown identity contract %q", name)
	}

	facts, err := c.derive(fields)
	if err != nil {
		return nil, err
	}

	// A contract that emits something it never declared is a bug in the
	// contract, and it would slip past a template's disclosure list unchecked.
	for key := range facts.Values {
		if !slices.Contains(c.produces, key) {
			return nil, fmt.Errorf("identity contract %q emitted undeclared fact %q; refusing", name, key)
		}
	}

	// Invariants enforced for every contract, present and future. These run
	// here rather than at the call site because this is the boundary a mistake
	// would cross, and because a caller cannot be relied on to re-check them.
	if err := assertNoEcho(facts, fields); err != nil {
		return nil, err
	}
	if err := assertPrintable(facts); err != nil {
		return nil, err
	}
	return facts, nil
}

// Reveal projects derived facts through the template's disclosure list,
// returning only what the template asked for, under the names it chose.
//
// This is where the template stays the authority. A contract computes
// everything it knows how to compute; the PROVIDER TEMPLATE decides which of
// those components are exposed to a caller. A daemon that always returned the
// contract's full output would be making a disclosure decision that belongs to
// the reviewable, signed artifact — and would silently widen what is revealed
// every time a contract learned to compute something new.
//
// disclose maps output name -> contract fact name, matching the direction of
// the deliver block's existing map: (output key on the left). A fact the
// contract did not produce is omitted rather than blanked, so a template cannot
// invent an empty field that reads as a real answer.
func (f *Facts) Reveal(disclose map[string]string) *Facts {
	out := make(map[string]string, len(disclose))
	for name, fact := range disclose {
		if v, ok := f.Values[fact]; ok {
			out[name] = v
		}
	}
	return &Facts{Contract: f.Contract, Values: out, Source: f.Source, Offline: f.Offline}
}

// assertNoEcho refuses any derived value that contains one of the inputs.
//
// This is the invariant that survives a hostile provider template. A template
// declares which fields are secret, so a malicious one could try to route a
// secret into a contract by reclassifying or renaming it. That gains nothing if
// no contract can return what it was given: derivation must COMPUTE its answer,
// never pass one through.
func assertNoEcho(facts *Facts, fields map[string]string) error {
	for name, in := range fields {
		if in == "" {
			continue
		}
		for key, out := range facts.Values {
			if strings.Contains(out, in) {
				return fmt.Errorf("identity contract %q returned input field %q in output %q; refusing (contracts must compute, never echo)",
					facts.Contract, name, key)
			}
		}
	}
	return nil
}

// assertPrintable rejects control characters in derived values. Facts are
// printed to terminals and merged into JSON, so a value carrying escapes or
// newlines could rewrite what a user sees.
func assertPrintable(facts *Facts) error {
	for key, v := range facts.Values {
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("identity contract %q returned a control character in %q; refusing", facts.Contract, key)
			}
		}
	}
	return nil
}

// ─── AWS ──────────────────────────────────────────────────────────────────

// awsKeyPrefixes maps the 4-character resource prefix of an AWS access key id
// to what kind of key it is. The prefix is not decorative: it distinguishes a
// long-lived IAM user key from a temporary STS one, which tells a reader
// whether "these credentials expired" is even a possibility.
//
// It doubles as the allowlist for what this contract will decode at all. An id
// with an unrecognised prefix is refused rather than decoded on the assumption
// that the layout still holds.
var awsKeyPrefixes = map[string]string{
	"AKIA": "long-term access key",
	"ASIA": "temporary (STS) access key",
	"AROA": "role",
	"AIDA": "IAM user",
	"ANPA": "managed policy",
	"ANVA": "policy version",
	"ABIA": "bearer token",
	"ACCA": "context-specific credential",
}

// awsAccountFromAccessKey decodes the AWS account number embedded in an access
// key id.
//
// AWS assigns key ids as base32 of a binary structure whose bits 7..47 are the
// account number. This is a property of the id format, not a secret: the
// account number appears in every ARN the account emits. Recovering it locally
// means the question is answered instantly, offline, and — importantly — still
// answered after the key is deactivated, when sts:GetCallerIdentity returns
// InvalidClientTokenId and tells you nothing.
//
// Only the access key id is read, and neither it nor any part of it is
// returned: the outputs are a computed number and a fixed enum string.
func awsAccountFromAccessKey(fields map[string]string) (*Facts, error) {
	keyID := strings.TrimSpace(fields["access_key_id"])
	if keyID == "" {
		return nil, fmt.Errorf("credential has no access_key_id to derive an account from")
	}

	account, kind, err := decodeAWSAccessKeyID(keyID)
	if err != nil {
		return nil, err
	}

	return &Facts{
		Contract: ContractAWSAccessKeyAccountID,
		Values:   map[string]string{"account_id": account, "key_type": kind},
		Source:   "decoded from the access key id (no network call; valid even if the key is deactivated)",
		Offline:  true,
	}, nil
}

// awsKeyIDLen is the exact length of an AWS access key id: a 4-character
// resource prefix plus 16 base32 characters.
const awsKeyIDLen = 20

// decodeAWSAccessKeyID validates an access key id strictly and returns the
// account number and key kind.
//
// Validation is deliberately unforgiving. A malformed-but-base32-decodable
// string would otherwise yield a plausible 12-digit number, and a confidently
// wrong account number is worse than an error: it is the input to "am I about
// to act on prod?".
func decodeAWSAccessKeyID(keyID string) (account, kind string, err error) {
	if len(keyID) != awsKeyIDLen {
		return "", "", fmt.Errorf("access key id %q is %d characters, expected %d — refusing to guess an account from it",
			redactKeyID(keyID), len(keyID), awsKeyIDLen)
	}
	prefix := strings.ToUpper(keyID[:4])
	kind, ok := awsKeyPrefixes[prefix]
	if !ok {
		return "", "", fmt.Errorf("access key id %q has unrecognised prefix %q — refusing to decode an unknown id layout",
			redactKeyID(keyID), prefix)
	}

	payload := keyID[4:]
	// Reject lowercase rather than folding it: a real AWS id is uppercase, and
	// silently normalising input is how a near-miss becomes a wrong answer.
	if payload != strings.ToUpper(payload) {
		return "", "", fmt.Errorf("access key id %q is not canonical uppercase base32", redactKeyID(keyID))
	}
	raw, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(payload)
	if decErr != nil {
		return "", "", fmt.Errorf("access key id %q is not valid base32: %w", redactKeyID(keyID), decErr)
	}
	if len(raw) < 6 {
		return "", "", fmt.Errorf("access key id %q decoded to %d bytes, need 6", redactKeyID(keyID), len(raw))
	}

	// accountMask selects bits 7..47 of the leading 6 bytes; the low 7 bits are
	// not part of the account number.
	const accountMask = 0x7fffffffff80
	var buf [8]byte
	copy(buf[2:], raw[:6])
	n := (binary.BigEndian.Uint64(buf[:]) & accountMask) >> 7

	// AWS account numbers are canonically 12 digits, zero-padded.
	return fmt.Sprintf("%012s", strconv.FormatUint(n, 10)), kind, nil
}

// redactKeyID keeps error messages useful without echoing a full identifier
// into logs: enough to tell two keys apart, not enough to correlate.
func redactKeyID(keyID string) string {
	if len(keyID) <= 8 {
		return "…"
	}
	return keyID[:4] + "…" + keyID[len(keyID)-4:]
}
