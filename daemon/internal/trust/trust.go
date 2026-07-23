// Package trust is the approval gate for provider plugins. There are no
// compiled-in providers and any file in the template search path can declare a
// high-trust effect (today: owning an agent session's environment). Trust is
// therefore explicit and per-template: a sensitive capability is applied only
// if a human has approved that template, and the approval is bound to the
// file's SHA-256 so a post-approval edit (TOCTOU / swap) revokes it until
// re-approved. Trust will later also be conferred by a publisher signature on
// the shipped bundle; this store is the local, user-granted half.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/publisher"
	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Record is one template's recorded approval.
type Record struct {
	SHA256       string   `json:"sha256"`
	Capabilities []string `json:"capabilities"`
	Origin       string   `json:"origin"`
	ApprovedAt   string   `json:"approved_at"`
}

// Store is the on-disk approval set, keyed by template name.
type Store struct {
	path    string
	Records map[string]Record
}

// Path is the approvals file location. AKASHA_APPROVALS_FILE overrides the
// default ~/.akasha/approvals.json.
func Path() string {
	if p := os.Getenv("AKASHA_APPROVALS_FILE"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "approvals.json")
}

// Load reads the approvals store from the default path.
func Load() (*Store, error) { return LoadFrom(Path()) }

// LoadFrom reads the approvals store from a specific path. A missing file is an
// empty store, not an error.
func LoadFrom(path string) (*Store, error) {
	s := &Store{path: path, Records: map[string]Record{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.Records); err != nil {
			return nil, fmt.Errorf("approvals file %s is corrupt: %w", path, err)
		}
	}
	return s, nil
}

// Save writes the store back to disk (0600, parent dir 0700).
func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.Records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// FileSHA256 returns the hex SHA-256 of a file's contents.
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Approve records approval of a template's current file for its current
// sensitive capabilities. Caller saves.
func (s *Store) Approve(t *template.Template) error {
	if t.Origin() == "" {
		return fmt.Errorf("template %q has no source file to approve", t.Name)
	}
	sum, err := FileSHA256(t.Origin())
	if err != nil {
		return err
	}
	s.Records[t.Name] = Record{
		SHA256:       sum,
		Capabilities: t.SensitiveCapabilities(),
		Origin:       t.Origin(),
		ApprovedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	return nil
}

// Revoke removes a template's approval. Returns whether anything was removed.
func (s *Store) Revoke(name string) bool {
	if _, ok := s.Records[name]; ok {
		delete(s.Records, name)
		return true
	}
	return false
}

// ApprovedFunc loads the store and returns a predicate reporting whether a
// template is approved. A load error denies all (fail closed). Handy for the
// discovery/ownership gates that take a `trusted func(*template.Template) bool`.
func ApprovedFunc() func(*template.Template) bool {
	s, err := Load()
	return func(t *template.Template) bool {
		if err != nil || s == nil {
			return false
		}
		ok, _ := s.Approved(t)
		return ok
	}
}

// Approved reports whether t's current file is approved for every sensitive
// capability it currently declares. Approval comes from either:
//   - a valid signature by a trusted publisher (official or user-trusted) — the
//     hands-off path for the shipped bundle and marketplace plugins; or
//   - an explicit, hash-bound manual approval in this store — for unsigned
//     local development.
// A template with no sensitive capabilities is always approved. A capability
// gained since approval, a changed file hash, or a broken signature makes it
// not approved.
func (s *Store) Approved(t *template.Template) (bool, error) {
	caps := t.SensitiveCapabilities()
	if len(caps) == 0 {
		return true, nil
	}
	// Signature by a trusted publisher confers trust without a local record.
	if t.Origin() != "" {
		if _, ok, err := publisher.VerifyTemplate(t.Origin()); err == nil && ok {
			return true, nil
		}
	}
	rec, ok := s.Records[t.Name]
	if !ok || t.Origin() == "" {
		return false, nil
	}
	sum, err := FileSHA256(t.Origin())
	if err != nil {
		return false, err
	}
	if rec.SHA256 != sum {
		return false, nil // file changed since approval
	}
	have := make(map[string]bool, len(rec.Capabilities))
	for _, c := range rec.Capabilities {
		have[c] = true
	}
	for _, c := range caps {
		if !have[c] {
			return false, nil
		}
	}
	return true, nil
}
