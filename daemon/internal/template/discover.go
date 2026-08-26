package template

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"net/url"
	"sort"
)

// Discovery engine: executes the declarative `discover` sources of loaded
// templates. Read-only by design — it returns findings; vaulting is the
// caller's decision.
//
// This is the ONLY discovery path. aws, git and ssh were once scanned by
// hand-written Go in internal/discover, which meant three provider names lived
// in the daemon, the shipped templates described discovery that never ran, and
// the file reading those scanners did was invisible to the trust gate. They are
// now ordinary templates whose `discover` blocks enumerate every location read.
//
// That is the extensibility contract, applied uniformly: drop a datadog.yaml
// with a discover block and `akasha setup` / `akasha discover` finds and vaults
// it with no daemon change — exactly as the shipped providers do.

// Finding is one discovered credential instance.
type Finding struct {
	Provider string            // template name the fields map onto
	Instance string            // named instance ("default", profile, host…)
	Fields   map[string]string // credential field → raw value
	Source   string            // display path of where it was found
	Risk     string
	Shadowed []string // sources of same-label findings this one takes precedence over
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
		switch t.Kind {
		case KindDiscovery:
			out = append(out, runDiscover(t.Provider, t.Discover)...)
		case KindProvider:
			out = append(out, runDiscover(t.Name, t.Discover)...)
		}
	}
	// Both passes run over ALL findings rather than per template, because a
	// discovery artifact and the provider it names produce the same labels from
	// two different loop iterations, and a collision between those two is no
	// less a collision.
	return resolveLabels(dedupe(out))
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

// dedupe collapses the same credential found in more than one place, keeping
// the first occurrence — which is the earliest `discover` rule, so a template
// orders its sources most-authoritative-first and gets that for free.
//
// The common case is real: an AWS `default` profile usually appears in both
// ~/.aws/credentials and ~/.aws/config, and reporting it twice would vault it
// twice and show the user a duplicate they have to reason about.
//
// Identity is (provider, instance, field values) rather than any one field,
// because this engine has no provider knowledge — it cannot know that
// access_key_id is the identifying one. Two genuinely different profiles that
// happen to share a key stay separate, which is the safer error: they are
// different names the user may have different intentions for.
//
// This collapses only what is IDENTICAL. Same instance, different values is a
// contest over one label, and resolveLabels below settles it.
func dedupe(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		keys := make([]string, 0, len(f.Fields))
		for k := range f.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString(f.Provider)
		b.WriteByte(0)
		b.WriteString(f.Instance)
		for _, k := range keys {
			b.WriteByte(0)
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(f.Fields[k])
		}
		if seen[b.String()] {
			continue
		}
		seen[b.String()] = true
		out = append(out, f)
	}
	return out
}

// resolveLabels enforces here what the vault enforces anyway: one credential
// per "provider:instance". A finding becomes a label, and a label points at one
// token, so two findings that name the same instance with DIFFERENT values are
// not two entries — they are two candidates for one entry.
//
// Nothing used to notice. Both were vaulted, both printed "✓ vaulted", and the
// second silently replaced the first: on a machine with a shared credentials
// file AND a stale `export AWS_ACCESS_KEY_ID` in ~/.zshrc — the pairing our own
// fixtures model — `aws:default` resolved to whichever the loop reached last,
// which was the .zshrc copy. That inverts the order every template documents
// ("MOST AUTHORITATIVE FIRST"): dedupe honours it, but only for byte-identical
// findings, and a rotated key is precisely the case where they differ.
//
// So the first finding wins, which is the earliest `discover` rule, which is
// the order the template declares. The losers are not dropped quietly — each is
// recorded on the winner so the review step can show the user the file it did
// NOT take, with a name for the choice that was made on their behalf.
//
// Which makes source order a decision a template author now has to make on
// purpose, along an axis that is DURABILITY, not the precedence the provider's
// own SDK applies. aws.yaml lists ~/.aws/credentials above the process
// environment even though the AWS SDK resolves the environment first: the label
// is permanent, and an exported AWS_* that disagrees with the file is usually an
// assume-role session that expires within the hour. Vaulting the copy that is
// live in one shell right now, under a name meant to outlast it, produces a
// credential that stops working for no visible reason.
func resolveLabels(findings []Finding) []Finding {
	at := make(map[string]int, len(findings)) // provider:instance → index in out
	out := findings[:0]
	for _, f := range findings {
		label := f.Provider + ":" + f.Instance
		if i, taken := at[label]; taken {
			out[i].Shadowed = append(out[i].Shadowed, f.Source)
			continue
		}
		at[label] = len(out)
		out = append(out, f)
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
		return globbed(d, discoverINI)
	case "env-lines":
		return globbed(d, discoverEnvLines)
	case "json", "yaml":
		return globbed(d, discoverDoc)
	case "file":
		return discoverFiles(d)
	case "env":
		return discoverProcessEnv(d)
	case "url-lines":
		return globbed(d, discoverURLLines)
	default:
		return nil
	}
}

// ─── url-lines ─────────────────────────────────────────────────────────────

// discoverURLLines parses a file of one-credential-per-line URLs — the shape
// git's credential store uses (`https://user:token@host`), and the same shape
// pip.conf, .npmrc registries, and similar tools embed credentials in.
//
// The reserved map values name the URL's parts:
//
//	map: {token: password, user: username, host: host}
//
// `password` falls back to the username when a URL carries only one userinfo
// component, which is how a bare token is usually written (`https://ghp_x@host`).
// Instance defaults to the hostname, so one file yields one instance per host.
func discoverURLLines(d DiscoverSource, path string) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	display := displayPath(path)
	var out []Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.User == nil {
			continue
		}
		password, ok := u.User.Password()
		if !ok {
			password = u.User.Username()
		}
		parts := map[string]string{
			"password": password,
			"username": u.User.Username(),
			"host":     u.Hostname(),
			"scheme":   u.Scheme,
		}
		fields := map[string]string{}
		for field, part := range d.Map {
			if v := parts[part]; v != "" {
				fields[field] = v
			}
		}
		if len(fields) == 0 {
			continue
		}
		// Lower-cased because a hostname is case-insensitive by definition, and
		// the instance becomes the label a credential helper is scoped by:
		// GitHub.com and github.com in the same store are one host with one
		// token, not two instances the user has to reason about.
		inst := strings.ToLower(u.Hostname())
		if d.Instances == "single" {
			inst = "default"
		}
		out = append(out, Finding{Instance: inst, Fields: fields, Source: display})
	}
	return out
}

// globbed runs a single-file parser over every path matching d.Path, so one
// rule can name a family of files (`~/.env*`) rather than needing one entry per
// name. A path with no glob metacharacters resolves to itself, so this is
// transparent for the common case.
//
// Globbing lives here rather than in each parser so every file-reading source
// gains it identically, and so the traversal guard in runSource covers them all.
func globbed(d DiscoverSource, parse func(DiscoverSource, string) []Finding) []Finding {
	expanded := expandPath(d.Path)
	swept := strings.ContainsAny(expanded, "*?[")
	paths, err := filepath.Glob(expanded)
	if err != nil {
		return nil
	}
	if paths == nil && !swept {
		paths = []string{expanded} // literal path; absence is handled by the stat below
	}
	sort.Strings(paths) // deterministic order regardless of directory listing
	var out []Finding
	for _, p := range paths {
		if swept && isPlaceholderFile(p) {
			continue
		}
		// Only regular files are parsed. Opening a FIFO blocks until a writer
		// appears, so a single named pipe matching a declared path — `~/.env*`
		// catches one called `.env.fifo` — hung the whole run with no output,
		// `--dry-run` included. Every parser below opens what it is handed, so
		// the check belongs here, before the handoff.
		//
		// Stat, not Lstat: it follows the link and tests the TARGET, which is
		// the behaviour wanted twice over. A symlinked ~/.aws/credentials is
		// ordinary (chezmoi, stow, any dotfiles repo) and must still be read,
		// while a symlink pointing AT a fifo must not be. A dangling link or a
		// symlink loop fails the stat and is skipped rather than hanging.
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, parse(d, p)...)
	}
	return out
}

// ─── process environment ───────────────────────────────────────────────────

// discoverProcessEnv reads credential fields straight from this process's
// environment. d.Map values are the environment variable names.
//
// This is the one discovery source with no file behind it, and it is why AWS
// discovery needed hand-written Go: a credential exported into the shell was
// invisible to every file-based rule. As a named primitive it is available to
// every provider — Azure, GCP, or anything a user writes — instead of being a
// hard-coded property of three built-in scanners.
func discoverProcessEnv(d DiscoverSource) []Finding {
	fields := map[string]string{}
	for field, envVar := range d.Map {
		if v := os.Getenv(envVar); v != "" {
			fields[field] = v
		}
	}
	if len(fields) == 0 {
		return nil
	}
	inst := d.Instances
	if inst == "" || inst == "single" {
		inst = "env"
	}
	return []Finding{{Instance: inst, Fields: fields, Source: "environment"}}
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

// placeholderSuffixes name files that exist in order to be COPIED: the
// committed half of a .env pair, carrying AWS_ACCESS_KEY_ID=your-key-here.
//
// `~/.env*` sweeps them up, and a placeholder is a finding like any other — it
// vaults, it labels, and it competes for `aws:default` against the credential
// that actually works. Since resolveLabels now settles that contest by declared
// order rather than by whichever was written last, a sample file sitting in a
// glob ahead of a real one would WIN it, so this is part of that fix and not a
// tidy-up next to it.
//
// Only for a path that was swept up by a glob. A rule that names such a file
// outright is asking for it, and gets it.
var placeholderSuffixes = []string{".example", ".sample", ".template", ".dist"}

func isPlaceholderFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	for _, s := range placeholderSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// ─── quoting ────────────────────────────────────────────────────────────────

// quotedValue returns the contents of a value written between matching quotes,
// discarding whatever follows the closing quote — so both parsers below agree
// on what a quote means, and neither vaults the quotes themselves.
//
// Storing them verbatim was defensible and is what botocore does: AWS's own ini
// reader keeps the quotes, so `aws_access_key_id = "AKIA…"` is broken in the
// file too. Fidelity is the wrong goal HERE, though, because Akasha does not
// hand the file to the SDK — it hands over a value it read, out of a vault the
// user cannot inspect (values are never printed, by design). The quotes would
// resurface days later as a signature error from a remote API, naming nothing
// the user could go and look at. The trailing `# comment` case is worse: it
// only ends up in the value because the quote that terminated it was ignored.
//
// An UNQUOTED value keeps a `#` that sits INSIDE a word — `secret#notacomment`
// is a secret, not a comment — and withoutInlineComment below draws the other
// half of that line. Only a quoted value has an unambiguous end, so nothing
// here truncates a credential mid-word on a guess.
// The quote CHARACTER is returned too, because the two quotes do not mean the
// same thing to a shell and envValue has to tell them apart: inside single
// quotes a `$` is an ordinary character, inside double quotes it starts an
// expansion.
func quotedValue(v string) (inner string, quote byte, ok bool) {
	if v == "" || (v[0] != '"' && v[0] != '\'') {
		return "", 0, false
	}
	end := strings.IndexByte(v[1:], v[0])
	if end < 0 {
		return "", 0, false // unterminated — not quoting, don't guess at where it ends
	}
	return v[1 : 1+end], v[0], true
}

// withoutInlineComment drops a `# comment` / `; comment` written after an
// unquoted value on the same line. The marker has to START a word, so the env
// parser's shell-word rule and this one agree on what a `#` means, and a hash
// in the middle of a secret survives both.
//
// Keeping the comment was the conservative choice while the LAST source to be
// read won a label. It stopped being conservative when the first declared
// source started winning instead: `aws_access_key_id =   # set me` in
// ~/.aws/credentials — source #1 for aws — otherwise takes aws:default away
// from the key that works, and `AKIA… # rotate me quarterly` hands the SDK a
// value with a sentence glued to it. Neither is visible afterwards: the vault
// never prints what it holds, so both surface days later as an authentication
// error naming nothing the user can go and look at.
func withoutInlineComment(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] != '#' && v[i] != ';' {
			continue
		}
		if i == 0 || v[i-1] == ' ' || v[i-1] == '\t' {
			return v[:i]
		}
	}
	return v
}

// ─── ini ────────────────────────────────────────────────────────────────────

var iniSection = regexp.MustCompile(`^\[(?:profile\s+)?(.+?)\]`)

// discoverINI parses an ini-style file. instances: sections (default) names
// each section; a sectionless file yields instance "default". d.Map values
// are the ini keys (matched case-insensitively).
func discoverINI(d DiscoverSource, path string) []Finding {
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
			if inner, _, quoted := quotedValue(strings.TrimSpace(v)); quoted {
				v = inner
			} else {
				v = strings.TrimSpace(withoutInlineComment(v))
			}
			if v == "" {
				continue // a key with no value is not a credential, here as in a .env
			}
			current.Fields[field] = v
		}
	}
	flush()
	return out
}

// ─── env-lines ──────────────────────────────────────────────────────────────

// envLine splits an assignment from the rest of the line. The value is matched
// loosely and interpreted by envValue below, rather than being constrained
// here: the previous pattern required no space around `=` and allowed no
// whitespace or quote in the value, so `export AWS_ACCESS_KEY_ID = "AKIA…"`
// matched nothing at all. That did not fail — it silently produced HALF a
// credential, because the neighbouring secret line happened to be written in a
// form the pattern accepted, and half a credential vaults, labels, and reports
// "✓ vaulted" like any other.
var envLine = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

// envValue reads the value half of an assignment the way a shell would.
func envValue(raw string) (string, bool) {
	// Quoted, so spaces and `#` are part of the value and the closing quote ends
	// it — that is what makes `KEY="has spaces in it"` a credential rather than
	// a miss, and `KEY='v'  # note` a value rather than a value plus a comment.
	v, quote, quoted := quotedValue(raw)
	if !quoted {
		// A quote that never closes is a typo, not a value continuing on some
		// other line, and skipping the field is the costlier way to be wrong:
		// the sibling line still parses, so the run vaults HALF a credential —
		// the exact failure this parser was loosened to stop. Drop the stray
		// quote and read the rest as a word. (The ini parser keeps such a value
		// verbatim instead: ini has no quoting rules to typo, so a leading `"`
		// there may well be part of the value.)
		v = raw
		if v != "" && (v[0] == '"' || v[0] == '\'') {
			v = v[1:]
		}
		// Unquoted, so a shell word: it ends at the first space, which is also
		// what drops a trailing ` # comment`. `secret#notacomment` keeps its
		// hash — the shell only starts a comment at the start of a word.
		v = strings.TrimLeft(v, " \t")
		if i := strings.IndexAny(v, " \t"); i >= 0 {
			v = v[:i]
		}
		if strings.HasPrefix(v, "#") {
			// The word IS the start of a comment, so the assignment has no
			// value at all. Reading `#` as one is not a cosmetic error: a
			// `.env` full of `AWS_ACCESS_KEY_ID=   # set me` is declared ahead
			// of the file holding the real key, so under first-wins it would
			// TAKE aws:default and shadow it, and no listing can show that
			// happened because values are never printed.
			return "", false
		}
	}
	// Single quotes are the shell's literal quote: `KEY='$ecret'` IS the value
	// `$ecret`, and blanking it produced exactly the half credential the parser
	// was loosened to stop — a leading `$` is ordinary in a generated password.
	// Double-quoted and unquoted values DO expand, so a `$` there really can be
	// a reference to a secret rather than one.
	if quote != '\'' {
		v = withoutExpansion(v)
	}
	return v, v != ""
}

// withoutExpansion blanks a value that is a REFERENCE to a credential, not one:
// `export AWS_SECRET_ACCESS_KEY=$(pass aws)`, `${AWS_KEY}`, a backticked
// command. Nothing here runs a shell, so the literal text is all there is, and
// vaulting `$(pass` would produce a credential that fails at first use.
//
// Deliberately narrow — leading `$`/backtick, or a literal `$(` anywhere. A `$`
// in the MIDDLE of a word is an ordinary character in a great many passwords,
// and dropping those would trade a rare false positive for a common false
// negative.
func withoutExpansion(v string) string {
	if v == "" {
		return v
	}
	if v[0] == '$' || v[0] == '`' || strings.Contains(v, "$(") {
		return ""
	}
	return v
}

// discoverEnvLines scans KEY=VALUE / export KEY=value lines (.env files,
// shell configs). d.Map values are the env var names to capture.
func discoverEnvLines(d DiscoverSource, path string) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Case-insensitive, like the ini parser: the two disagreed about what they
	// matched, so `aws_access_key_id=…` was a credential in ~/.aws/credentials
	// and invisible in a .env. Whether the SDK would read it back is not the
	// question — it is a live key sitting in a file either way.
	wantVar := invertLower(d.Map) // env var name (lower) → credential field
	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if m := envLine.FindStringSubmatch(line); m != nil {
			field, want := wantVar[strings.ToLower(m[1])]
			if !want {
				continue
			}
			if v, ok := envValue(strings.TrimSpace(m[2])); ok {
				fields[field] = v
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
func discoverDoc(d DiscoverSource, path string) []Finding {
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
//
//	map: {private_key: content}
func discoverFiles(d DiscoverSource) []Finding {
	paths, err := filepath.Glob(expandPath(d.Path))
	if err != nil {
		return nil
	}
	match := matchers[d.Match]
	var out []Finding
	for _, path := range paths {
		// Regular files only — see the matching guard in globbed(). IsDir() was
		// the wrong predicate: it excludes directories but admits fifos, device
		// nodes and sockets, and this source opens what it matches (the matcher
		// head-read below, then ReadFile). ssh.yaml declares `path: ~/.ssh/*`,
		// so a fifo named ~/.ssh/id_anything reached that open and hung.
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
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

func invertLower(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for field, key := range m {
		out[strings.ToLower(key)] = field
	}
	return out
}
