package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// The audit log used to record vault tokens verbatim. On a real install that is
// hundreds of live tokens sitting in a file, which is the enumeration primitive
// an attacker wants: read the log, pick a token, retrieve it. Closing the
// retrieval paths while leaving the map on the table is half a fix.
//
// Tokens are DIGESTED rather than masked or dropped, because the only thing the
// log ever does with a token is correlate: this VAULTED, those RETRIEVEDs and
// that DENIED all concern the same secret. Nothing in the CLI, the SDK or the
// tests reads a token back out of the log — `akasha logs` decodes into a generic
// map and re-prints. A stable digest preserves equality across events, which is
// the entire semantic, while being useless as a credential.
//
// The digest is deliberately unkeyed. Tokens carry 64 bits from crypto/rand, so
// there is no dictionary to grind and no preimage to guess — and an unkeyed
// digest means no key to store, rotate, back up, or migrate, and correlation
// that survives across daemon restarts and vault rebuilds.

// tokenPattern matches the two identifier shapes the daemon mints:
// vault://<11 base64url chars> (8 random bytes) and grt://<16> (12 bytes).
// Matching by shape rather than by field is what catches a token that a caller
// embedded in free text.
var tokenPattern = regexp.MustCompile(`\b(vault|grt)://[A-Za-z0-9_-]{8,32}`)

// redactToken replaces one identifier with a stable digest of itself.
// An empty string stays empty so `omitempty` still elides the field.
func redactToken(tok string) string {
	if tok == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tok))
	return "tk_" + hex.EncodeToString(sum[:])[:12]
}

// redactText rewrites any token-shaped substring inside caller-supplied prose.
//
// Task, ReasoningTrace and TriggeredBy are written by the agent and copied into
// the log verbatim, so redacting only the Token field would leave a second,
// wider channel open — an agent that wanted its tokens in the log could simply
// put them in the task description.
func redactText(s string) string {
	if s == "" {
		return s
	}
	return tokenPattern.ReplaceAllStringFunc(s, redactToken)
}

// redacted returns a copy of e with every token-bearing field digested.
//
// This runs on the drain goroutine rather than in Emit, so a request handler
// never pays for it.
func redacted(e Event) Event {
	e.Token = redactToken(e.Token)
	e.GrantID = redactToken(e.GrantID)
	e.Task = redactText(e.Task)
	e.ReasoningTrace = redactText(e.ReasoningTrace)
	e.TriggeredBy = redactText(e.TriggeredBy)
	return e
}
