// Package assume turns vaulted credential maps into ready-to-use, short-lived
// credential files in each provider's native format. The agent never receives
// raw secret strings — only a file path and the env vars to set. This removes
// the entire class of "agent fumbles the secret" errors: there is no unsafe
// way to use a handle the agent never holds in raw form.
//
// Providers are declarative templates (internal/template) registered by
// template_writer.go; adding one is a single YAML file, builtin or dropped
// into ~/.akasha/templates/. The lone exception is "env" (env.go), the
// universal fallback whose dynamic field names a fixed schema can't express.
package assume

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Result is what the agent receives: env vars to set, the file path, and TTL.
// On the agent-facing path the env never carries a raw secret — a provider whose
// env delivery would materialize a secret field is refused upstream (see
// handleAssume) rather than returning the value.
type Result struct {
	Provider  string            `json:"provider"`
	Profile   string            `json:"profile"`
	Env       map[string]string `json:"env"`
	Path      string            `json:"path,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// DefaultTTL is how long an assumed credential file lives before cleanup.
const DefaultTTL = time.Hour

// writer materializes a resolved credential set into a provider-native form.
// dir is the session directory; creds are decrypted field→value pairs.
type writer func(dir, profile string, creds map[string]string, expires time.Time) (*Result, error)

// providers is the registry. Every real provider (aws, gcp, github, gitlab,
// git, ssh, and anything dropped into ~/.akasha/templates/) is template-backed
// and registered by template_writer.go's init. The only Go writer left is
// "env": its field names ARE the env var names, which a fixed-field schema
// cannot express — it is the universal fallback mechanism, not a provider.
var providers = map[string]writer{
	"env": writeEnv,
}

// safeName constrains provider/profile to characters that cannot traverse
// directories or inject path separators / newlines. This blocks writing a
// session credential file outside ~/.akasha/sessions and INI/header injection
// via the profile name.
var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Write materializes credentials for a provider and returns a Result.
// creds is the decrypted credential map (field → real value).
func Write(provider, profile string, creds map[string]string, ttl time.Duration) (*Result, error) {
	if !safeName.MatchString(provider) || !safeName.MatchString(profile) {
		return nil, fmt.Errorf("invalid provider/profile: only letters, digits, '.', '_', '-' allowed")
	}
	// Reject the dot-only names ("." / "..") that the charset would otherwise permit.
	if profile == "." || profile == ".." || provider == "." || provider == ".." {
		return nil, fmt.Errorf("invalid provider/profile")
	}
	w, ok := writerFor(provider)
	if !ok {
		// Distinguish "no such provider" from "this provider loaded, but every
		// delivery route it declares is newer than this daemon". The second is
		// a version skew the user can act on, and it used to be invisible: the
		// template was rejected outright, so the provider simply did not exist
		// and the error blamed the wrong thing.
		if t := template.Get(provider); t != nil {
			return nil, fmt.Errorf(
				"provider %q is loaded but cannot be assumed by this daemon: none of the delivery routes it declares are supported here. Run `akasha template list` to see what was dropped, and upgrade the daemon if its bundle is newer",
				provider)
		}
		return nil, fmt.Errorf("unsupported provider for assume: %q", provider)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	dir, err := sessionDir()
	if err != nil {
		return nil, err
	}
	// Opportunistic sweep on every assume, plus the background sweeper.
	SweepExpired()
	return w(dir, profile, creds, time.Now().Add(ttl).UTC())
}

// SupportedProviders returns the assumable provider names (for help text): the
// hand-written Go writers plus every provider template with a file/env deliver
// mode, deduped. Resolved live so a dropped-in template shows up immediately.
func SupportedProviders() []string {
	set := make(map[string]bool, len(providers))
	for k := range providers {
		set[k] = true
	}
	for _, name := range templateProviderNames() {
		set[name] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

// ─── Shared helpers ───────────────────────────────────────────────────────

// sessionBase, if set, overrides where credential files are written. The daemon
// points this at a RAM-backed (tmpfs / RAM disk) location so secrets never touch
// physical disk. Set once at startup via SetSessionBase.
var sessionBase string

// SetSessionBase overrides the parent directory of the sessions folder. Pass a
// RAM-backed mount (e.g. a tmpfs path on Linux or a RAM disk on macOS) so
// assumed credential files live only in memory.
func SetSessionBase(dir string) { sessionBase = dir }

// sessionDir is where short-lived credential files are written (0700). It
// prefers a RAM-backed location so the files never reach the SSD, walking the
// candidates in order and using the first one it can prove is private:
//   1. an explicit SetSessionBase override (a RAM disk the daemon mounted)
//   2. $XDG_RUNTIME_DIR (tmpfs on Linux)
//   3. /dev/shm (tmpfs on Linux)
//   4. ~/.akasha (physical disk fallback — still 0600 + TTL-swept)
//
// /dev/shm is world-writable (mode 1777), so on a multi-user host another local
// account can create akasha-<uid> — a directory of its own, or a symlink
// pointing wherever it likes — before this daemon ever runs. A candidate that
// fails verification is skipped rather than fatal: a hostile /dev/shm must cost
// the user a slower location, not a working assume.
func sessionDir() (string, error) {
	var last error
	for _, base := range sessionBases() {
		if err := ensurePrivateDir(base); err != nil {
			last = err
			continue
		}
		dir := filepath.Join(base, "sessions")
		if err := ensurePrivateDir(dir); err != nil {
			last = err
			continue
		}
		return dir, nil
	}
	if last == nil {
		last = fmt.Errorf("no candidate location exists")
	}
	return "", fmt.Errorf("no private directory to write credential files into (%v) — "+
		"point akasha at one you own with mode 0700", last)
}

// sessionBases lists the candidate parents of the sessions directory, best
// first. The membership test on the enclosing tmpfs stays a plain Stat: whether
// /dev/shm is itself a symlink (some distros link it to /run/shm) says nothing
// about who controls the akasha directory inside it, and that is the thing
// ensurePrivateDir proves.
func sessionBases() []string {
	var out []string
	if sessionBase != "" {
		out = append(out, sessionBase)
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && isDir(d) {
		out = append(out, filepath.Join(d, "akasha"))
	}
	if isDir("/dev/shm") {
		out = append(out, filepath.Join("/dev/shm", fmt.Sprintf("akasha-%d", os.Getuid())))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, filepath.Join(home, ".akasha"))
	}
	return out
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// ensurePrivateDir creates dir if it is missing and then proves it is a real
// directory this uid owns that no other user can reach. MkdirAll's mode applies
// only to directories it creates, so a squatted path arrives with the
// attacker's mode and MkdirAll reports success: the verification after the
// create, not the create, is what decides.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return verifyPrivateDir(dir)
}

// verifyPrivateDir checks with Lstat, never Stat: Stat follows symlinks, so it
// reports on the attacker's target instead of the planted link.
func verifyPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink, not a directory — remove it, or point akasha at a directory you own", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory — remove it so akasha can create the directory it writes credential files into", dir)
	}
	uid, ok := ownerUID(fi)
	if !ok {
		return fmt.Errorf("%s sits on a filesystem that reports no ownership, so credential files there cannot be kept "+
			"private — use a directory under your home", dir)
	}
	if uid != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not by you (uid %d) — its owner could read or replace the credential "+
			"files inside it; remove it or use a directory you own", dir, uid, os.Getuid())
	}
	perm := fi.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	// Tighten rather than trust: a mount point (the macOS RAM disk) and the data
	// dir both arrive group- or other-readable, and the fix is one chmod away.
	if err := os.Chmod(dir, perm&^0o077); err != nil {
		return fmt.Errorf("%s is mode %04o, so other users can reach the credential files inside it — chmod 0700 %s", dir, perm, dir)
	}
	fi, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s could not be made private (now mode %04o) — chmod 0700 %s", dir, fi.Mode().Perm(), dir)
	}
	return nil
}

// ownerUID reports the owning uid, and whether the filesystem supplied one.
func ownerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// writeSessionFile writes data to a 0600 file in the session dir and stamps the
// file's modification time with its expiry. Encoding expiry as mtime lets the
// sweeper enforce each file's own TTL — a 30s assume dies at 30s, a 1h assume
// at 1h — without a separate index. Returns the file path.
func writeSessionFile(dir, name string, data []byte, expires time.Time) (string, error) {
	path := filepath.Join(dir, name)
	// Containment backstop: the write must land directly inside the session
	// dir. deliver.name is charset-validated at load, but this guarantees that
	// even a name slipping past that check (a traversal like "../../.zshrc")
	// can never write a credential file outside the session directory.
	if filepath.Dir(path) != filepath.Clean(dir) {
		return "", fmt.Errorf("refusing to write session file outside the session dir: %q", name)
	}
	// The lexical check above stops "../" in the name but says nothing about a
	// symlink sitting at the leaf, which would send a private key to a path its
	// planter chose. Anything that is not our own leftover credential file is
	// refused; a leftover is unlinked (unlink never follows the link it removes)
	// so the create below can insist on making the file itself.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("refusing to write the session credential file: %s is a symlink or special file, "+
				"not a credential file left by an earlier assume — remove it", path)
		}
		if uid, ok := ownerUID(fi); ok && uid != os.Getuid() {
			return "", fmt.Errorf("refusing to write the session credential file: %s is owned by uid %d, not by you "+
				"(uid %d) — remove it", path, uid, os.Getuid())
		}
		if err := os.Remove(path); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", fmt.Errorf("cannot create the session credential file %s — remove whatever occupies that path: %v", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	// mtime == expiry; atime is irrelevant but must be supplied.
	if err := os.Chtimes(path, expires, expires); err != nil {
		return "", err
	}
	return path, nil
}

// SweepExpired deletes every session credential file whose expiry (encoded as
// its mtime) is in the past. Safe to call concurrently and on every assume; it
// is also driven on a timer by the daemon so a credential file self-destructs
// at its TTL even if no further assume ever happens. Returns count removed.
func SweepExpired() int {
	dir, err := sessionDir()
	if err != nil {
		return 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	now := time.Now()
	removed := 0
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(now) {
			if os.Remove(filepath.Join(dir, e.Name())) == nil {
				removed++
			}
		}
	}
	return removed
}

// ParseCredMap parses a credential map stored as JSON.
func ParseCredMap(jsonStr string) (map[string]string, error) {
	var m map[string]string
	err := json.Unmarshal([]byte(jsonStr), &m)
	return m, err
}
