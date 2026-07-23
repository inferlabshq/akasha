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
	"time"
)

// Result is what the agent receives: env vars to set, the file path, and TTL.
// Env never contains a raw secret on the agent-facing path — secret-valued env
// vars are redacted upstream and explained in Note.
type Result struct {
	Provider  string            `json:"provider"`
	Profile   string            `json:"profile"`
	Env       map[string]string `json:"env"`
	Path      string            `json:"path,omitempty"`
	Note      string            `json:"note,omitempty"`
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
// prefers a RAM-backed location so the files never reach the SSD:
//   1. an explicit SetSessionBase override (a RAM disk the daemon mounted)
//   2. $XDG_RUNTIME_DIR (tmpfs on Linux)
//   3. /dev/shm (tmpfs on Linux)
//   4. ~/.akasha (physical disk fallback — still 0600 + TTL-swept)
func sessionDir() (string, error) {
	base := resolveSessionBase()
	dir := filepath.Join(base, "sessions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func resolveSessionBase() string {
	if sessionBase != "" {
		return sessionBase
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && isDir(d) {
		return filepath.Join(d, "akasha")
	}
	if isDir("/dev/shm") {
		return filepath.Join("/dev/shm", fmt.Sprintf("akasha-%d", os.Getuid()))
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha")
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
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
	if err := os.WriteFile(path, data, 0600); err != nil {
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
