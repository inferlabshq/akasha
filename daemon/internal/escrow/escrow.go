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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// AgentID marks escrow entries in the vault. Deliberately NOT one of the
	// discovery agent IDs: escrowed originals exist ONLY in the vault, so
	// they must count in the "vault-only secrets" warning before a purge.
	AgentID  = "akasha-protect"
	Category = "EscrowedFile"

	// Provider is the policy provider name an escrow label resolves to, so
	// rules can be written against `provider: escrow` (see docs/POLICY.md).
	Provider = "escrow"

	// LabelPrefix namespaces escrow labels: "escrow:<absolute path>".
	LabelPrefix = Provider + ":"

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

// RestoredOnDisk reports whether the envelope in blob is currently back on disk
// at path, byte for byte — the only honest answer to "does this file exist
// anywhere other than the vault?", which is what every removal or re-pointing
// of an escrow label turns on.
//
// "Is the file on disk a stub?" was the proxy used before, and a proxy is not
// good enough here because the thing it inspects is caller-controlled: an agent
// that the escrow gate refuses to let near /label/delete can still WRITE that
// path, and any non-stub bytes it leaves there — one space will do — made the
// daemon answer "restored, safe to remove". The removal that followed took the
// original with it.
//
// A false answer is the safe one: it costs a `akasha restore` (or a named
// --destroy-escrowed-original), while a wrong true costs the file.
func RestoredOnDisk(blob, path string) bool {
	var env Envelope
	// A mismatched Path is what Restore itself refuses on, so an envelope that
	// cannot be restored to this name has no on-disk copy under it either.
	if err := json.Unmarshal([]byte(blob), &env); err != nil || env.Path != path {
		return false
	}
	// Lstat before opening. A non-regular file — a fifo above all — must never
	// be opened from a request handler: the open alone blocks until a writer
	// appears, and this runs in the daemon. It is not a copy of the original in
	// any case. The size check then bounds the read below to the length of the
	// user's own escrowed file.
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != int64(len(env.Content)) {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// Digests rather than a byte-wise walk: the comparison is against the
	// plaintext of a vault entry, and an early exit on the first differing byte
	// would time out where it stopped.
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	var onDisk [sha256.Size]byte
	copy(onDisk[:], h.Sum(nil))
	return onDisk == sha256.Sum256(env.Content)
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
#
# That command is for the human who owns this file: it asks for confirmation
# at a terminal, and the daemon refuses to hand an escrowed original to an
# agent identity at all. Running it from an agent session will fail.
`, Marker, path, path))
}

// Options tune Protect. The zero value is the safe default.
type Options struct {
	// AllowHardlinked escrows a file that has other hardlinks anyway.
	//
	// Off by default because the whole claim of protect — the plaintext now
	// exists ONLY in the vault — is false for such a file: replacing this name
	// leaves every other name pointing at the untouched inode, still readable
	// by anything that can reach it.
	AllowHardlinked bool
}

// Protect escrows path with the safe defaults: vault the exact bytes + mode,
// label the entry, and only then replace the file with a stub. Returns the
// vault token.
func Protect(v Vault, path string) (string, error) { return ProtectWith(v, path, Options{}) }

// ProtectWith is Protect with the caller's Options.
func ProtectWith(v Vault, path string, opt Options) (string, error) {
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
	// A hardlinked file cannot be protected by replacing THIS name: rename
	// swaps one directory entry, and the plaintext inode survives under every
	// other one. Escrowing it anyway would report success for a file whose
	// secret is still on disk — the one outcome protect must never produce.
	// Refuse, and name the sibling link when it is cheap to find.
	if !opt.AllowHardlinked {
		if n := hardlinkCount(fi); n > 1 {
			return "", fmt.Errorf("%s has %d hardlinks — escrowing it would leave the plaintext readable "+
				"through the other one%s. Break the link first (`cp %s %s.unlinked && mv %s.unlinked %s`), "+
				"remove the other link, or pass --allow-hardlinked to escrow this name anyway",
				abs, n, namedSibling(abs, fi), abs, abs, abs, abs)
		}
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

// hardlinkCount reports how many names the file has.
//
// An unreadable link count returns 1 rather than refusing: Stat_t is present on
// every platform this daemon builds for, so a miss here means an environment we
// do not ship to, and turning that into a blanket "protect is broken" would be
// a worse failure than the one it guards against.
func hardlinkCount(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 1
	}
	return uint64(st.Nlink)
}

// namedSibling looks for another link to the same inode in the file's OWN
// directory — the common case (`credentials` and `credentials.bak`) — so the
// refusal can name the file that still holds the secret. Best effort: one
// readdir, no recursion, and empty when it finds nothing. A filesystem-wide
// inode search is not something to run inside a protect.
func namedSibling(abs string, fi os.FileInfo) string {
	dir := filepath.Dir(abs)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if p == abs {
			continue
		}
		other, err := os.Lstat(p)
		if err != nil || !other.Mode().IsRegular() {
			continue
		}
		if os.SameFile(fi, other) {
			return " (" + p + ")"
		}
	}
	return ""
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
