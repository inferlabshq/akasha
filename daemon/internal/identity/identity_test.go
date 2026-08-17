package identity

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// encodeAccessKeyID builds an access key id carrying the given account number,
// independently of the decoder under test: it packs the account into bits 7..47
// and base32-encodes the result the way AWS does.
//
// Written as a separate construction (shift up, encode) from the decoder
// (decode, mask, shift down) so a wrong mask or shift shows up as a mismatch
// instead of cancelling out.
func encodeAccessKeyID(prefix string, account uint64, tail byte) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], account<<7)
	raw := make([]byte, 10)
	copy(raw, buf[2:]) // leading 6 bytes carry the account
	raw[6], raw[7], raw[8], raw[9] = tail, tail, tail, tail
	return prefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

func TestAccountIDRoundTrip(t *testing.T) {
	for _, want := range []uint64{
		716969406655, // 12 digits, high bits set
		204000719911, // the other real-world shape
		1,            // pathological low
		999999999999, // largest 12-digit
		29608264753,  // 11 digits — must zero-pad to 12
	} {
		account, _, err := decodeAWSAccessKeyID(encodeAccessKeyID("AKIA", want, 'A'))
		if err != nil {
			t.Fatalf("account %d: %v", want, err)
		}
		if account != fmt.Sprintf("%012d", want) {
			t.Errorf("account %d: got %q", want, account)
		}
		if len(account) != 12 {
			t.Errorf("account %d: got %q, want 12 digits", want, account)
		}
	}
}

// The low 7 bits are not part of the account number, so keys differing only
// there must resolve to the same account.
func TestAccountIDIgnoresLowBits(t *testing.T) {
	const account = 716969406655
	first, _, err := decodeAWSAccessKeyID(encodeAccessKeyID("AKIA", account, 'A'))
	if err != nil {
		t.Fatal(err)
	}
	second, kind, err := decodeAWSAccessKeyID(encodeAccessKeyID("ASIA", account, 'Z'))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("same account, different key tail: %q != %q", first, second)
	}
	if kind != "temporary (STS) access key" {
		t.Errorf("ASIA should decode as temporary, got %q", kind)
	}
}

// A confidently wrong account number is worse than an error — it is the input
// to "am I about to act on prod?". Anything that is not exactly an AWS access
// key id must be refused, not decoded on optimistic assumptions.
func TestDecodeRefusesRatherThanGuesses(t *testing.T) {
	valid := encodeAccessKeyID("AKIA", 716969406655, 'A')
	cases := map[string]string{
		"empty":              "",
		"too short":          valid[:19],
		"too long":           valid + "A",
		"unknown prefix":     "XXXX" + valid[4:],
		"lowercase payload":  valid[:4] + strings.ToLower(valid[4:]),
		"not base32":         "AKIA1111111111111111", // 1 and 8 are absent from RFC4648 base32
		"prefix only":        "AKIA",
		"plausible garbage":  "AKIAAAAAAAAAAAAAAAA!",
		"whitespace padding": " " + valid[:19],
	}
	for name, keyID := range cases {
		if account, _, err := decodeAWSAccessKeyID(keyID); err == nil {
			t.Errorf("%s: expected refusal, got account %q", name, account)
		}
	}
}

// Errors must not echo a full key id into logs, but must stay specific enough
// to tell two keys apart.
func TestErrorRedactsKeyID(t *testing.T) {
	full := "AKIA1111111111111111"
	_, _, err := decodeAWSAccessKeyID(full)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), full) {
		t.Errorf("error leaked the full key id: %v", err)
	}
	if !strings.Contains(err.Error(), "AKIA") {
		t.Errorf("error dropped the distinguishing prefix: %v", err)
	}
}

func TestDeriveAWSFacts(t *testing.T) {
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	facts, err := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})
	if err != nil {
		t.Fatal(err)
	}
	if facts.Values["account_id"] != "716969406655" {
		t.Errorf("account_id = %q", facts.Values["account_id"])
	}
	if facts.Values["key_type"] != "long-term access key" {
		t.Errorf("key_type = %q", facts.Values["key_type"])
	}
	if !facts.Offline {
		t.Error("AWS derivation must be marked offline")
	}
}

// The access key id is derivation INPUT and must not come back out. Echoing it
// would put half the credential pair wherever facts are printed, logged, or
// stored, and would give a hostile template a pass-through.
func TestDeriveDoesNotEchoTheKeyID(t *testing.T) {
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	facts, err := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range facts.Values {
		if strings.Contains(v, keyID) {
			t.Errorf("fact %q echoed the access key id", k)
		}
	}
}

// The no-echo invariant must be enforced by Derive for EVERY contract, not left
// to each contract's good behaviour. A contract that passes its input through
// must be caught even though it produced no error itself.
func TestDeriveRejectsAnEchoingContract(t *testing.T) {
	const name = "test-echoing-contract"
	contracts[name] = contract{
		requires: []string{"leak_me"},
		produces: []string{"oops"}, // declared, so the echo check is what rejects it
		derive: func(f map[string]string) (*Facts, error) {
			return &Facts{Contract: name, Values: map[string]string{"oops": f["leak_me"]}}, nil
		},
	}
	t.Cleanup(func() { delete(contracts, name) })

	_, err := Derive(name, map[string]string{"leak_me": "super-secret-value"})
	if err == nil {
		t.Fatal("Derive must refuse a contract that echoes its input")
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Errorf("the refusal itself leaked the value: %v", err)
	}
}

// Even a substring of an input is a partial disclosure and must be refused.
func TestDeriveRejectsPartialEcho(t *testing.T) {
	const name = "test-partial-echo"
	contracts[name] = contract{
		requires: []string{"secret"},
		produces: []string{"prefix"},
		derive: func(f map[string]string) (*Facts, error) {
			return &Facts{Contract: name, Values: map[string]string{"prefix": "the value is " + f["secret"]}}, nil
		},
	}
	t.Cleanup(func() { delete(contracts, name) })

	if _, err := Derive(name, map[string]string{"secret": "abc123"}); err == nil {
		t.Fatal("Derive must refuse a value that merely contains its input")
	}
}

// Facts are printed to terminals. A derived value carrying escapes could
// rewrite what the user sees — including the account number next to it.
func TestDeriveRejectsControlCharacters(t *testing.T) {
	const name = "test-escape-contract"
	contracts[name] = contract{
		requires: []string{"x"},
		produces: []string{"account_id"},
		derive: func(map[string]string) (*Facts, error) {
			return &Facts{Contract: name, Values: map[string]string{
				"account_id": "111111111111\x1b[2K\raccount_id  999999999999",
			}}, nil
		},
	}
	t.Cleanup(func() { delete(contracts, name) })

	if _, err := Derive(name, map[string]string{"x": "y"}); err == nil {
		t.Fatal("Derive must refuse control characters in derived values")
	}
}

func TestDeriveRejectsMissingFieldAndUnknownContract(t *testing.T) {
	if _, err := Derive(ContractAWSAccessKeyAccountID, map[string]string{}); err == nil {
		t.Error("expected an error when access_key_id is absent")
	}
	if _, err := Derive("no-such-contract", map[string]string{}); err == nil {
		t.Error("expected an error for an unknown contract")
	}
}

// RequiredFields is what limits how much of a credential gets decrypted, so it
// must name only non-secret fields — never the secret half of the pair.
func TestRequiredFieldsIsMinimal(t *testing.T) {
	got, err := RequiredFields(ContractAWSAccessKeyAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "access_key_id" {
		t.Fatalf("AWS identity should need only access_key_id, got %v", got)
	}
	for _, f := range got {
		if strings.Contains(f, "secret") {
			t.Errorf("contract requires a secret-looking field %q", f)
		}
	}

	if _, err := RequiredFields("no-such-contract"); err == nil {
		t.Error("expected an error for an unknown contract")
	}
}

// Callers must not be able to mutate the contract's declared needs.
func TestRequiredFieldsReturnsACopy(t *testing.T) {
	got, _ := RequiredFields(ContractAWSAccessKeyAccountID)
	got[0] = "secret_access_key"
	again, _ := RequiredFields(ContractAWSAccessKeyAccountID)
	if again[0] != "access_key_id" {
		t.Fatalf("RequiredFields leaked its backing array: %v", again)
	}
}

func TestKnownMatchesNames(t *testing.T) {
	for _, n := range Names() {
		if !Known(n) {
			t.Errorf("Names() advertises %q but Known() rejects it", n)
		}
	}
	if Known("aws-sts-session-policy") {
		t.Error("mint contracts must not be accepted as identity contracts")
	}
}

// Reveal is where the template stays the authority: a contract computes
// everything it knows, and only what the provider template named is exposed.
func TestRevealDisclosesOnlyWhatTheTemplateAsksFor(t *testing.T) {
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	full, err := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Values) < 2 {
		t.Fatalf("expected the contract to compute more than one fact, got %v", full.Values)
	}

	// A template that reveals only the account number must not leak key_type.
	got := full.Reveal(map[string]string{"account_id": "account_id"})
	if len(got.Values) != 1 || got.Values["account_id"] != "716969406655" {
		t.Fatalf("Reveal exposed the wrong set: %v", got.Values)
	}
	if _, leaked := got.Values["key_type"]; leaked {
		t.Error("Reveal exposed a fact the template did not ask for")
	}
}

// A template may rename a fact on the way out, so the disclosed vocabulary is
// the provider's choice rather than the contract's internal naming.
func TestRevealRenames(t *testing.T) {
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	full, _ := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})

	got := full.Reveal(map[string]string{"aws_account": "account_id"})
	if got.Values["aws_account"] != "716969406655" {
		t.Fatalf("rename failed: %v", got.Values)
	}
}

// Nothing is disclosed by default. A contract that gains a new fact must not
// start revealing it through templates written before that fact existed.
func TestRevealDisclosesNothingByDefault(t *testing.T) {
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	full, _ := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})

	if got := full.Reveal(nil); len(got.Values) != 0 {
		t.Errorf("an empty disclosure list must reveal nothing, got %v", got.Values)
	}
}

// A template naming a fact the contract does not produce gets nothing, not an
// empty string that would read as a real answer.
func TestRevealOmitsUnknownFacts(t *testing.T) {
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	full, _ := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})

	got := full.Reveal(map[string]string{"account_id": "account_id", "arn": "arn"})
	if _, present := got.Values["arn"]; present {
		t.Errorf("unproduced fact should be omitted, not blanked: %v", got.Values)
	}
}

// Produces is what template validation checks a disclosure list against, so it
// must match what the contract actually emits.
func TestProducesMatchesRealOutput(t *testing.T) {
	declared, err := Produces(ContractAWSAccessKeyAccountID)
	if err != nil {
		t.Fatal(err)
	}
	keyID := encodeAccessKeyID("AKIA", 716969406655, 'A')
	full, _ := Derive(ContractAWSAccessKeyAccountID, map[string]string{"access_key_id": keyID})
	for key := range full.Values {
		if !contains(declared, key) {
			t.Errorf("contract emitted %q but does not declare it in Produces", key)
		}
	}
	if _, err := Produces("no-such-contract"); err == nil {
		t.Error("expected an error for an unknown contract")
	}
}

// A contract emitting something it never declared would slip past the
// template's disclosure list unchecked, so Derive refuses it.
func TestDeriveRejectsUndeclaredFact(t *testing.T) {
	const name = "test-undeclared-fact"
	contracts[name] = contract{
		requires: []string{"x"},
		produces: []string{"declared"},
		derive: func(map[string]string) (*Facts, error) {
			return &Facts{Contract: name, Values: map[string]string{"sneaky": "value"}}, nil
		},
	}
	t.Cleanup(func() { delete(contracts, name) })

	if _, err := Derive(name, map[string]string{"x": "y"}); err == nil {
		t.Fatal("Derive must refuse a fact the contract did not declare")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
