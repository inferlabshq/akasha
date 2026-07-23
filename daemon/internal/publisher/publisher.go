// Package publisher holds the trust roots for signed plugins: the embedded
// official publisher key plus any publishers the user has chosen to trust. It
// answers one question — "is this template file validly signed by a publisher I
// trust?" — which is how a signed plugin (the shipped bundle, or a third-party
// plugin from a marketplace) becomes trusted without per-template approval.
package publisher

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/sign"
)

// officialPubRaw is the embedded official trust root. It is a documented
// placeholder until provisioned; the first non-comment, non-blank line is the
// base64 public key. Embedding the *public* key (not a provider) is the
// verification anchor — like a browser shipping root CAs.
//
//go:embed official.pub
var officialPubRaw string

// OfficialID is the publisher id recorded in signatures from the official key.
const OfficialID = "akasha-official"

// Publisher is a user-trusted signing identity.
type Publisher struct {
	Name   string `json:"name"`
	PubKey string `json:"pubkey"` // base64 Ed25519 public key
}

// Path is the user publishers file. AKASHA_PUBLISHERS_FILE overrides the
// default ~/.akasha/publishers.json.
func Path() string {
	if p := os.Getenv("AKASHA_PUBLISHERS_FILE"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "publishers.json")
}

// officialKey parses the embedded root, or returns ok=false if unprovisioned.
func officialKey() (ed25519.PublicKey, bool) {
	for _, line := range strings.Split(officialPubRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pub, err := sign.DecodePublicKey(line); err == nil {
			return pub, true
		}
		return nil, false // a present-but-bad key is not silently a different key
	}
	return nil, false
}

// LoadUser reads the user publisher set (id → Publisher). Missing file is empty.
func LoadUser() (map[string]Publisher, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Publisher{}, nil
		}
		return nil, err
	}
	out := map[string]Publisher{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("publishers file %s is corrupt: %w", Path(), err)
		}
	}
	return out, nil
}

func saveUser(m map[string]Publisher) error {
	if err := os.MkdirAll(filepath.Dir(Path()), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path(), data, 0600)
}

// Add records (or updates) a trusted publisher. The pubkey must be valid.
func Add(id, name, pubkeyB64 string) error {
	if id == "" {
		return fmt.Errorf("publisher id is required")
	}
	if id == OfficialID {
		return fmt.Errorf("%q is the embedded official publisher and cannot be overridden", OfficialID)
	}
	if _, err := sign.DecodePublicKey(pubkeyB64); err != nil {
		return err
	}
	m, err := LoadUser()
	if err != nil {
		return err
	}
	m[id] = Publisher{Name: name, PubKey: strings.TrimSpace(pubkeyB64)}
	return saveUser(m)
}

// Remove drops a trusted publisher. Returns whether one was removed.
func Remove(id string) (bool, error) {
	m, err := LoadUser()
	if err != nil {
		return false, err
	}
	if _, ok := m[id]; !ok {
		return false, nil
	}
	delete(m, id)
	return true, saveUser(m)
}

// Trusted returns every trusted publisher id → public key (official + user).
func Trusted() (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	if pub, ok := officialKey(); ok {
		out[OfficialID] = pub
	}
	m, err := LoadUser()
	if err != nil {
		return nil, err
	}
	for id, p := range m {
		if pub, err := sign.DecodePublicKey(p.PubKey); err == nil {
			out[id] = pub
		}
	}
	return out, nil
}

// VerifyTemplate reports whether templatePath carries a valid signature from a
// trusted publisher. ok is false (no error) when the file is unsigned or signed
// by an unknown/wrong key. The file is read fresh, so a post-signing edit fails.
func VerifyTemplate(templatePath string) (publisherID string, ok bool, err error) {
	sig, present, err := sign.LoadSignature(templatePath)
	if err != nil || !present {
		return "", false, err
	}
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return "", false, err
	}
	trusted, err := Trusted()
	if err != nil {
		return "", false, err
	}
	pub, known := trusted[sig.Publisher]
	if !known {
		return "", false, nil // signed, but not by a publisher we trust
	}
	if sig.Verify(content, pub) {
		return sig.Publisher, true, nil
	}
	return "", false, nil
}
