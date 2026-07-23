// Package sign provides Ed25519 signing and verification for provider plugins.
//
// A plugin is signed by a publisher; the signature is detached and travels next
// to the template as "<file>.sig". Trust in a signature is conferred by the
// publisher's public key — the official key is an embedded trust root, and a
// user may add third-party publisher keys (a marketplace: an author signs their
// plugin, the user trusts that author once, and every plugin from them is
// accepted). Editing a signed file breaks its signature, so tamper is caught.
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Signature is the detached signature stored as "<file>.sig".
type Signature struct {
	Publisher string `json:"publisher"` // publisher id, resolved to a key by the trust store
	Alg       string `json:"alg"`       // "ed25519"
	Sig       string `json:"sig"`       // base64 (std) of the Ed25519 signature
}

const algEd25519 = "ed25519"

// GenerateKey returns a new Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// EncodeKey/DecodeKey render keys as base64 for on-disk and on-the-wire use.
func EncodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

func DecodeKey(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Sign produces a detached signature over content for the named publisher.
func Sign(content []byte, publisher string, priv ed25519.PrivateKey) Signature {
	return Signature{
		Publisher: publisher,
		Alg:       algEd25519,
		Sig:       base64.StdEncoding.EncodeToString(ed25519.Sign(priv, content)),
	}
}

// Verify reports whether the signature is a valid Ed25519 signature over
// content by pub. A wrong algorithm or malformed signature is simply invalid.
func (s Signature) Verify(content []byte, pub ed25519.PublicKey) bool {
	if s.Alg != algEd25519 || len(pub) != ed25519.PublicKeySize {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, content, raw)
}

// SigPath is the conventional signature path for a template file.
func SigPath(templatePath string) string { return templatePath + ".sig" }

// LoadSignature reads "<templatePath>.sig" if present. The bool is false (with
// nil error) when no signature file exists — unsigned is a normal state.
func LoadSignature(templatePath string) (*Signature, bool, error) {
	data, err := os.ReadFile(SigPath(templatePath))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var s Signature
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, fmt.Errorf("signature %s is malformed: %w", SigPath(templatePath), err)
	}
	return &s, true, nil
}

// WriteSignature writes a detached signature next to a template file (0644 —
// signatures are public).
func WriteSignature(templatePath string, s Signature) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(SigPath(templatePath), data, 0644)
}

// LoadPrivateKey reads a base64-encoded Ed25519 private key from a file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := DecodeKey(trimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("private key %s is not valid base64: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("private key has wrong length (expected an Ed25519 private key)")
	}
	return ed25519.PrivateKey(raw), nil
}

// DecodePublicKey parses a base64-encoded Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := DecodeKey(trimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public key has wrong length (expected an Ed25519 public key)")
	}
	return ed25519.PublicKey(raw), nil
}

// trimSpace removes surrounding whitespace/newlines from key files without
// pulling in strings for one call.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
