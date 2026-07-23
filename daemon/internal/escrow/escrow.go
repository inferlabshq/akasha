// Package escrow implements `akasha protect` / `akasha restore`: moving a
// plaintext credential file INTO the vault (possession) and back out,
// byte-for-byte verbatim.
//
// discover only ever vaults copies — the original stays on disk, readable by
// any process. Escrow closes that gap for users who opt in: the file's exact
// bytes and mode are stored as a vault entry, a comment-only stub replaces it
// on disk (dead plaintext path; INI-style tools fall through to their
// credential_process route), and `akasha restore` regenerates the original
// exactly. Ordering is durability-first: the vault entry and label are
// committed before the plaintext is touched, so a crash mid-protect can never
// lose the only copy.
package escrow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// AgentID marks escrow entries in the vault. Deliberately NOT one of the
	// discovery agent IDs: escrowed originals exist ONLY in the vault, so
	// they must count in the "vault-only secrets" warning before a purge.
	AgentID  = "akasha-protect"
	Category = "EscrowedFile"

	// LabelPrefix namespaces escrow labels: "escrow:<absolute path>".
	LabelPrefix = "escrow:"

	// Marker identifies a stub. Protect refuses any file containing it —
	// escrowing a stub over a real envelope would destroy the original.
	Marker = "AKASHA-ESCROWED-FILE"
)

// Vault is the narrow storage surface escrow needs. Satisfied directly by
// *vault.Vault (via Direct) and by the CLI's daemon-socket adapter.
type Vault interface {
	Store(plaintext, category, risk, agentID, toolName string, ttl time.Duration) (string, error)
	ValueForLabel(name string) (string, error)
	SetLabel(name, token string) error
	ListLabels(prefix string) ([]string, error)
}

// Envelope is the vaulted representation of an escrowed file. Content
// round-trips through JSON as base64, so arbitrary bytes survive verbatim.
type Envelope struct {
	Version int    `json:"version"`
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Content []byte `json:"content"`
}

// Label returns the escrow label for a path (absolute, cleaned).
func Label(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return LabelPrefix + filepath.Clean(abs), nil
}

// IsStub reports whether file content is an escrow stub.
func IsStub(content []byte) bool {
	return strings.Contains(string(content), Marker)
}

// StubContent renders the comment-only file left at the original path. Every
// line is #-prefixed so INI-family consumers (AWS credentials, gitconfig)
// parse it as empty and fall through to their credential_process route.
func StubContent(path string) []byte {
	return []byte(fmt.Sprintf(`# %s — do not edit, do not commit.
#
# The original %s has been moved into the Akasha vault.
# Tools that were reading this file now obtain credentials through the
# akasha daemon (credential_process / credential helper), per-use and audited.
#
# Restore the original file exactly as it was with:
#   akasha restore %s
`, Marker, path, path))
}

// Protect escrows path: vault the exact bytes + mode, label the entry, and
// only then replace the file with a stub. Returns the vault token.
func Protect(v Vault, path string) (string, error) {
	label, err := Label(path)
	if err != nil {
		return "", err
	}
	abs := strings.TrimPrefix(label, LabelPrefix)

	fi, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink — escrow the real file it points to", abs)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", abs)
	}

	content, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	if IsStub(content) {
		return "", fmt.Errorf("%s is already an escrow stub — the original is in the vault (restore it with `akasha restore %s`)", abs, abs)
	}

	env := Envelope{Version: 1, Path: abs, Mode: uint32(fi.Mode().Perm()), Content: content}
	blob, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	// Durability first: entry + label are committed before the plaintext is
	// touched. A crash after this point leaves BOTH copies (safe); a crash
	// before it leaves only the original (also safe). Re-protecting a real
	// file overwrites the label; the superseded entry becomes an orphan.
	token, err := v.Store(string(blob), Category, "critical", AgentID, "akasha_protect", 0)
	if err != nil {
		return "", err
	}
	if err := v.SetLabel(label, token); err != nil {
		return "", err
	}

	if err := replaceFile(abs, StubContent(abs), 0600); err != nil {
		return "", fmt.Errorf("escrowed to %s but could not replace the file (original untouched): %w", token, err)
	}
	return token, nil
}

// Restore regenerates the escrowed original at path, byte-for-byte with its
// original mode. Idempotent: restoring an already-restored file rewrites the
// same bytes. The vault entry stays (re-protect overwrites it).
func Restore(v Vault, path string) error {
	label, err := Label(path)
	if err != nil {
		return err
	}
	abs := strings.TrimPrefix(label, LabelPrefix)

	blob, err := v.ValueForLabel(label)
	if err != nil {
		return fmt.Errorf("no escrowed original for %s: %w", abs, err)
	}
	var env Envelope
	if err := json.Unmarshal([]byte(blob), &env); err != nil {
		return fmt.Errorf("corrupt escrow envelope for %s: %w", abs, err)
	}
	if env.Path != abs {
		return fmt.Errorf("escrow envelope path mismatch: label says %s, envelope says %s", abs, env.Path)
	}
	return replaceFile(abs, env.Content, os.FileMode(env.Mode))
}

// List returns the absolute paths of all escrowed files.
func List(v Vault) ([]string, error) {
	labels, err := v.ListLabels(LabelPrefix)
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(labels))
	for i, l := range labels {
		paths[i] = strings.TrimPrefix(l, LabelPrefix)
	}
	return paths, nil
}

// IsEscrowed reports whether path currently has an escrow label.
func IsEscrowed(v Vault, path string) bool {
	label, err := Label(path)
	if err != nil {
		return false
	}
	labels, err := v.ListLabels(label)
	if err != nil {
		return false
	}
	for _, l := range labels {
		if l == label {
			return true
		}
	}
	return false
}

// replaceFile writes content atomically (temp file + rename in the same
// directory) so a crash never leaves a half-written credential file.
func replaceFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".akasha-escrow-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
