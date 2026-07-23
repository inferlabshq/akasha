package template

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Discovery engine: executes the declarative `discover` sources of loaded
// templates. Read-only by design — it returns findings; vaulting is the
// caller's decision.
//
// The hand-tuned Go scanners in internal/discover stay authoritative for the
// providers in NativeScanners (they cover env vars, .env files, shell configs,
// and dedup heuristics a declarative rule can't express yet), so this engine
// runs only:
//   - discover blocks of provider templates NOT owned by a native scanner, and
//   - kind:discovery artifacts.
// That is the extensibility contract: drop a datadog.yaml with a discover
// block and `akasha setup` / `akasha discover` finds and vaults it with no
// daemon change.

// Finding is one discovered credential instance.
type Finding struct {
	Provider string            // template name the fields map onto
	Instance string            // named instance ("default", profile, host…)
	Fields   map[string]string // credential field → raw value
	Source   string            // display path of where it was found
	Risk     string
}

// DiscoverUser runs the discover block of every TRUSTED provider template not
// owned by a native scanner, plus every trusted discovery artifact, returning
// all findings. Reading the file paths a template names is a gated capability
// (CapReadFiles), so trusted reports whether a template is approved — an
// untrusted discovery template is not run at all, so it can't read a file.
// Unreadable paths and malformed files are skipped silently: discovery must
// never fail setup.
func DiscoverUser(trusted func(*Template) bool) []Finding {
	var out []Finding
	for _, t := range All() {
		if !trusted(t) {
			continue
		}
		switch {
		case t.Kind == KindDiscovery:
			out = append(out, runDiscover(t.Provider, t.Discover)...)
		case t.Kind == KindProvider && !NativeScanners[t.Name]:
			out = append(out, runDiscover(t.Name, t.Discover)...)
		}
	}
	return out
}

func runDiscover(provider string, sources []DiscoverSource) []Finding {
	var out []Finding
	for _, d := range sources {
		for _, f := range runSource(d) {
			f.Provider = provider
			f.Risk = d.Risk
			if !safeName.MatchString(f.Instance) {
				continue // instance becomes a label/file component — drop unsafe names
			}
			out = append(out, f)
		}
	}
	return out
}

func runSource(d DiscoverSource) []Finding {
	// Defence in depth: refuse parent-dir traversal in a declared path, so even
	// a trusted template can't walk out to an unexpected location.
	for _, seg := range strings.Split(d.Path, "/") {
		if seg == ".." {
			return nil
		}
	}
	switch d.Source {
	case "ini":
		return discoverINI(d)
	case "env-lines":
		return discoverEnvLines(d)
	case "json", "yaml":
		return discoverDoc(d)
	case "file":
		return discoverFiles(d)
	default:
		return nil
	}
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

func displayPath(p string) string {
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}

// ─── ini ────────────────────────────────────────────────────────────────────

var iniSection = regexp.MustCompile(`^\[(?:profile\s+)?(.+?)\]`)

// discoverINI parses an ini-style file. instances: sections (default) names
// each section; a sectionless file yields instance "default". d.Map values
// are the ini keys (matched case-insensitively).
func discoverINI(d DiscoverSource) []Finding {
	path := expandPath(d.Path)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	wantKey := invertLower(d.Map) // ini key (lower) → credential field
	var out []Finding
	current := Finding{Instance: "default", Fields: map[string]string{}, Source: displayPath(path)}
	flush := func() {
		if len(current.Fields) > 0 {
			out = append(out, current)
		}
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if m := iniSection.FindStringSubmatch(line); m != nil {
			flush()
			current = Finding{Instance: m[1], Fields: map[string]string{}, Source: displayPath(path)}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if field, want := wantKey[strings.ToLower(strings.TrimSpace(k))]; want {
			current.Fields[field] = strings.TrimSpace(v)
		}
	}
	flush()
	return out
}

// ─── env-lines ──────────────────────────────────────────────────────────────

var envLine = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?([^"'\s]+)["']?\s*$`)

// discoverEnvLines scans KEY=VALUE / export KEY=value lines (.env files,
// shell configs). d.Map values are the env var names to capture.
func discoverEnvLines(d DiscoverSource) []Finding {
	path := expandPath(d.Path)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	wantVar := invert(d.Map) // env var name → credential field
	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if m := envLine.FindStringSubmatch(line); m != nil {
			if field, want := wantVar[m[1]]; want {
				fields[field] = m[2]
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return []Finding{{Instance: instanceName(d, path), Fields: fields, Source: displayPath(path)}}
}

// ─── json / yaml documents ──────────────────────────────────────────────────

// discoverDoc parses a JSON or YAML document. instances: keys treats each
// top-level key as an instance whose value object holds the credential keys;
// instances: single (default) reads credential keys from the top level.
func discoverDoc(d DiscoverSource) []Finding {
	path := expandPath(d.Path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]interface{}
	// yaml.v3 parses JSON too (YAML is a superset).
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}

	pick := func(obj map[string]interface{}) map[string]string {
		fields := map[string]string{}
		for field, key := range d.Map {
			if v, ok := obj[key].(string); ok && v != "" {
				fields[field] = v
			}
		}
		return fields
	}

	display := displayPath(path)
	if d.Instances == "keys" {
		var out []Finding
		for inst, v := range doc {
			obj, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			if fields := pick(obj); len(fields) > 0 {
				out = append(out, Finding{Instance: inst, Fields: fields, Source: display})
			}
		}
		return out
	}
	if fields := pick(doc); len(fields) > 0 {
		return []Finding{{Instance: instanceName(d, path), Fields: fields, Source: display}}
	}
	return nil
}

// ─── file (whole-content credentials, e.g. key files) ──────────────────────

// matchers are the named content classifiers a `file` source may reference.
// A matcher is a daemon primitive, same trust rule as parsers and contracts.
var matchers = map[string]func(head []byte) bool{
	"pem-private-key": func(head []byte) bool {
		s := string(head)
		return strings.Contains(s, "-----BEGIN") && strings.Contains(s, "PRIVATE KEY")
	},
}

// discoverFiles globs d.Path and emits one finding per matching file. The
// reserved map keys "content" and "filename" expose the file body and name:
//   map: {private_key: content}
func discoverFiles(d DiscoverSource) []Finding {
	paths, err := filepath.Glob(expandPath(d.Path))
	if err != nil {
		return nil
	}
	match := matchers[d.Match]
	var out []Finding
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if match != nil {
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			head := make([]byte, 256)
			n, _ := f.Read(head)
			f.Close()
			if !match(head[:n]) {
				continue
			}
		}
		var content string
		fields := map[string]string{}
		for field, key := range d.Map {
			switch key {
			case "content":
				if content == "" {
					data, err := os.ReadFile(path)
					if err != nil {
						continue
					}
					content = string(data)
				}
				fields[field] = content
			case "filename":
				fields[field] = filepath.Base(path)
			}
		}
		if len(fields) > 0 {
			out = append(out, Finding{Instance: filepath.Base(path), Fields: fields, Source: displayPath(path)})
		}
	}
	return out
}

// ─── helpers ────────────────────────────────────────────────────────────────

func instanceName(d DiscoverSource, path string) string {
	if d.Instances == "filename" {
		return filepath.Base(path)
	}
	return "default"
}

func invert(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for field, key := range m {
		out[key] = field
	}
	return out
}

func invertLower(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for field, key := range m {
		out[strings.ToLower(key)] = field
	}
	return out
}
