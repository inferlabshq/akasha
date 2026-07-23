package template

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Logf is the load-time logger. The daemon may point this at its own logger;
// it defaults to SILENT so one-shot CLI commands don't print a load line per
// template to stderr. The daemon sets it to log.Printf at startup so template
// capability/override lines land in the daemon log.
var Logf = func(string, ...any) {}

// SetLogf points template load logging at a real logger (the daemon does this).
func SetLogf(f func(string, ...any)) { Logf = f }

var (
	loadOnce sync.Once
	registry map[string]*Template
)

// There are no compiled-in providers. Every provider — aws, github, or a
// custom internal key — is a YAML file loaded from disk through one uniform
// path, with no privileged tier. Akasha ships a curated bundle as *data*
// (installed into ShippedDir), and a user can add to or override any of it by
// dropping a file in UserDir. Trust will come from signatures on the shipped
// bundle, never from being embedded in the binary.

// Dirs returns the template search path in precedence order: earlier dirs are
// loaded first, later dirs override same-named templates. AKASHA_TEMPLATES_PATH
// (os.PathListSeparator-joined) overrides the whole path; otherwise it is the
// shipped bundle followed by the user dir, so a user file overrides a shipped
// one of the same name.
func Dirs() []string {
	if p := os.Getenv("AKASHA_TEMPLATES_PATH"); p != "" {
		return filepath.SplitList(p)
	}
	return []string{ShippedDir(), UserDir()}
}

// ShippedDir holds the curated provider bundle Akasha installs as data (not
// compiled in). AKASHA_SHIPPED_TEMPLATES_DIR overrides the default.
func ShippedDir() string {
	if d := os.Getenv("AKASHA_SHIPPED_TEMPLATES_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "templates.dist")
}

// UserDir is where a user's own provider templates live. Drop a YAML file here
// to add a provider, or shadow a shipped one — no daemon change, no PR.
// AKASHA_TEMPLATES_DIR overrides the default ~/.akasha/templates.
func UserDir() string {
	if d := os.Getenv("AKASHA_TEMPLATES_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".akasha", "templates")
}

// Get returns the named template (builtin or user-supplied), or nil.
func Get(name string) *Template {
	load()
	return registry[name]
}

// All returns every loaded template, sorted by name.
func All() []*Template {
	load()
	out := make([]*Template, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Providers returns the loaded kind:provider templates, sorted by name.
func Providers() []*Template {
	var out []*Template
	for _, t := range All() {
		if t.Kind == KindProvider {
			out = append(out, t)
		}
	}
	return out
}

func load() {
	loadOnce.Do(func() {
		registry = map[string]*Template{}
		for _, dir := range Dirs() {
			loadDir(dir)
		}
	})
}

// loadDir loads every *.yaml in dir into the registry. Files are processed in
// sorted order for determinism. A same-named template overrides one already
// loaded (from an earlier dir on the search path) — that is how a user file in
// UserDir replaces a shipped one. Invalid files are skipped with a logged
// reason, and every accepted template gets a one-line capability log so "what
// can this thing do, and where did it come from" is on the record.
func loadDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // dir absent — fine; the search path is best-effort
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml")) {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			Logf("template: skipping %s: %v", path, err)
			continue
		}
		t, err := Parse(data)
		if err != nil {
			Logf("template: skipping %s: %v", path, err)
			continue
		}
		t.origin = path
		if existing, ok := registry[t.Name]; ok {
			Logf("template: %s overrides %q (was %s)", path, t.Name, existing.origin)
		}
		registry[t.Name] = t
		Logf("template: loaded %s (%s) — capabilities: %s", t.Name, path, t.Capabilities())
	}
}

// Parse decodes and validates one template document. Decoding is strict:
// unknown YAML keys are an error, so a typo'd block fails at load instead of
// being silently ignored.
func Parse(data []byte) (*Template, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var t Template
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// ResetForTest clears the registry so tests can exercise loading. Test-only.
func ResetForTest() {
	loadOnce = sync.Once{}
	registry = nil
}

// BundleDirForTest resolves the in-repo curated bundle (daemon/templates),
// absolutely, from this source file's location — so any package's tests can
// load the shipped providers regardless of the test working directory. Tests
// point AKASHA_TEMPLATES_PATH at it. Not for production: the installed daemon
// loads the bundle from ShippedDir, which the installer populates.
func BundleDirForTest() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Join(filepath.Dir(self), "..", "..", "templates")
}
