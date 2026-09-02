package template

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Logf is the load-time logger. The daemon may point this at its own logger;
// it defaults to SILENT so one-shot CLI commands don't print a load line per
// template to stderr. The daemon sets it to log.Printf at startup so template
// capability/override lines land in the daemon log.
var Logf = func(string, ...any) {}

// SetLogf points template load logging at a real logger (the daemon does this).
func SetLogf(f func(string, ...any)) { Logf = f }

// Skip records a template file that failed to load and why.
//
// Skips used to exist only as a log line, and Logf defaults to a no-op — so
// every CLI path reported nothing at all. A provider that failed to parse just
// vanished from `template list`, and the first symptom was `assume` failing for
// a provider the user could see in their templates directory. Recording skips
// lets the tooling show the file and the reason at the moment someone goes
// looking for the missing provider.
//
// This matters most across versions: a template using a primitive an older
// daemon does not know fails validation, and "aws is missing" is a much harder
// thing to debug than "aws.yaml: unknown mode \"describe\"".
type Skip struct {
	Path   string
	Reason string
}

var skipped []Skip

func recordSkip(path string, err error) {
	skipped = append(skipped, Skip{Path: path, Reason: err.Error()})
}

// FileDegradation is a Degradation with the file it came from.
type FileDegradation struct {
	Path string
	Degradation
}

var degradations []FileDegradation

// Degradations returns the capabilities dropped during the last load: templates
// that loaded and work, minus the parts this daemon is too old to implement.
//
// Reported rather than silent, because "your provider quietly lost a delivery
// route" is exactly the class of problem that is invisible until something
// fails much later, somewhere else.
func Degradations() []FileDegradation {
	load()
	out := make([]FileDegradation, len(degradations))
	copy(out, degradations)
	return out
}

// DegradationsFor returns the dropped capabilities for one template file.
func DegradationsFor(path string) []FileDegradation {
	var out []FileDegradation
	for _, d := range Degradations() {
		if d.Path == path {
			out = append(out, d)
		}
	}
	return out
}

// Skipped returns the template files that failed to load in the last load,
// in search-path order.
func Skipped() []Skip {
	load()
	out := make([]Skip, len(skipped))
	copy(out, skipped)
	return out
}

var (
	// loadMu guards every global below. It used to be a sync.Once, which made
	// the registry a PROCESS-LIFETIME snapshot — see load().
	loadMu      sync.Mutex
	registry    map[string]*Template
	loadedPrint string
	lastChecked time.Time

	// recheckEvery bounds how often the search path is stat'd. A var so tests
	// can set it to zero and see an edit immediately.
	recheckEvery = time.Second
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
	loadMu.Lock()
	defer loadMu.Unlock()
	loadLocked()
	return registry[name]
}

// All returns every loaded template, sorted by name.
func All() []*Template {
	loadMu.Lock()
	defer loadMu.Unlock()
	loadLocked()
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

// load populates the registry, reloading it when the files on the search path
// have changed.
//
// It was a sync.Once: read once, frozen for the life of the process. The trust
// store beside it is read fresh on every request, and store.Approved compares a
// digest taken from DISK against the one frozen here — two halves of one check
// with two different ideas of "now".
//
// The consequence was a provider that could not be repaired without a restart.
// Edit a trusted template, and the fresh on-disk digest no longer matches the
// stale in-memory one, so the template reads as untrusted; the error says to
// approve it, and approving it changes the file's recorded digest but not the
// frozen copy, so the next request fails identically. The remedy the message
// gives is the thing that was just done.
//
// The policy engine already solved this exact problem one package over: it
// re-reads policy.yaml on every gated operation and caches on the CONTENT
// digest, because "a control that must not be pinnable". Templates are the same
// kind of object and get the same treatment.
//
// The fingerprint is names, sizes and modification times, not file contents:
// this runs on a hot path, and the question is only "has anything changed",
// which a full re-read would answer at the cost of answering it. recheckEvery
// bounds the stat'ing; an edit lands within that window rather than instantly,
// which is the trade a lock-free hot path is worth.
func load() {
	loadMu.Lock()
	defer loadMu.Unlock()
	loadLocked()
}

func loadLocked() {
	now := time.Now()
	if registry != nil && now.Sub(lastChecked) < recheckEvery {
		return
	}
	lastChecked = now

	print := fingerprint()
	if registry != nil && print == loadedPrint {
		return
	}
	loadedPrint = print

	registry = map[string]*Template{}
	skipped = nil
	degradations = nil
	for _, dir := range Dirs() {
		loadDir(dir)
	}
}

// fingerprint summarises the search path cheaply enough to check often.
//
// A file that changes without changing its size or mtime is not detected, which
// is the standard limit of this approach and is acceptable here: the case being
// served is a person editing a template, and editors move mtime. A digest of
// every file would close it and would cost a full read of the whole search path
// on every check, which is the thing being avoided.
func fingerprint() string {
	var b strings.Builder
	for _, dir := range Dirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Absent directories are normal on this search path, and their
			// absence is itself part of the fingerprint: a bundle appearing
			// later has to count as a change.
			fmt.Fprintf(&b, "%s:absent\n", dir)
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				fmt.Fprintf(&b, "%s/%s:?\n", dir, e.Name())
				continue
			}
			fmt.Fprintf(&b, "%s/%s:%d:%d\n", dir, e.Name(), info.Size(), info.ModTime().UnixNano())
		}
	}
	return b.String()
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
			recordSkip(path, err)
			Logf("template: skipping %s: %v", path, err)
			continue
		}
		t, degraded, err := ParseLenient(data)
		if err != nil {
			recordSkip(path, err)
			Logf("template: skipping %s: %v", path, err)
			continue
		}
		for _, d := range degraded {
			degradations = append(degradations, FileDegradation{Path: path, Degradation: d})
			Logf("template: %s: dropped %s", path, d)
		}
		t.origin = path
		sum := sha256.Sum256(data)
		t.digest = hex.EncodeToString(sum[:])
		if existing, ok := registry[t.Name]; ok {
			Logf("template: %s overrides %q (was %s)", path, t.Name, existing.origin)
		}
		registry[t.Name] = t
		Logf("template: loaded %s (%s) — capabilities: %s", t.Name, path, t.Capabilities())
	}
}

// Parse decodes and validates one template document STRICTLY: unknown YAML
// keys are an error, and so is an unrecognised capability name. This is the
// authoring contract — `akasha template validate` and tests — where a typo must
// fail rather than quietly produce a template that does less than it says.
//
// The daemon loads through ParseLenient instead.
func Parse(data []byte) (*Template, error) {
	t, _, err := parse(data, &degradeCtx{strict: true})
	return t, err
}

// ParseLenient decodes a template the way the DAEMON should read one: unknown
// YAML keys remain an error (the document's shape must be understood), but a
// capability this daemon does not implement is dropped and reported instead of
// rejecting the whole file.
//
// This is what lets the primitive registry grow without lockstep upgrades. A
// bundle from a newer release names primitives an older daemon has never heard
// of; before this, one such name took the entire provider out — a template
// gaining a deliver mode lost `assume`, its credential helper, and
// `exec --assume` with it, silently. Now it loses exactly the capability the
// daemon cannot honour.
//
// Degradation never softens a security check: unknown agent ownership
// mechanisms and source backends stay fatal, as does any malformed known
// primitive. See degradeCtx.drop.
func ParseLenient(data []byte) (*Template, []Degradation, error) {
	dc := &degradeCtx{}
	t, dc, err := parse(data, dc)
	if err != nil {
		return nil, nil, err
	}
	return t, dc.found, nil
}

func parse(data []byte, dc *degradeCtx) (*Template, *degradeCtx, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Unknown KEYS stay fatal on both paths. A key defines what the document
	// means; a registry value only names a capability. That is the line the
	// frozen core draws (docs/PLUGIN_FORMAT.md), and it is why extension
	// happens through named primitives rather than new keys.
	dec.KnownFields(true)
	var t Template
	if err := dec.Decode(&t); err != nil {
		return nil, dc, fmt.Errorf("parse: %w", err)
	}
	if err := t.validate(dc); err != nil {
		return nil, dc, err
	}
	return &t, dc, nil
}

// ResetForTest clears the registry so tests can exercise loading. Test-only.
func ResetForTest() {
	loadMu.Lock()
	defer loadMu.Unlock()
	loadedPrint = ""
	lastChecked = time.Time{}
	registry = nil
	skipped = nil
	degradations = nil
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
