// Package template defines Akasha's declarative provider templates: YAML
// documents that describe how a credential provider's secrets are shaped,
// where they live on disk, and how they are delivered to agents. Templates
// are pure data — a strict schema, enum-bound primitives, and a whitelist
// placeholder substitution. There is deliberately no conditional or expression
// syntax: anything procedural (a parser, a wire protocol, a provider API
// call) is a named primitive implemented in the daemon, and a template may
// only select primitives by name. That constraint is what makes third-party
// templates reviewable as data rather than auditable as code.
//
// Two artifact kinds exist:
//   - "provider": the full five-block shape (credential / discover / deliver /
//     agent / mint). Deliver and agent blocks WRITE files and environment into
//     agent sessions, so providers are the high-trust kind.
//   - "discovery": read-only rules that locate credentials for an existing
//     provider. Parsed and validated today, executed by a later phase.
package template

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/identity"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
)

// Kind values for the top-level artifact type.
const (
	KindProvider  = "provider"
	KindDiscovery = "discovery"
)

// Enum registries. A template may only reference these by name; adding a new
// value is a daemon change, which is the intended trust boundary.
var (
	validSources   = set("ini", "json", "yaml", "file", "env-lines", "env", "url-lines")
	validInstances = set("sections", "keys", "filename", "single")
	validModes     = set("helper", "file", "env", "describe")
	// Helper wire formats are generic emit mechanisms (how bytes reach the
	// consumer's stdin/stdout protocol), never provider names. A provider is
	// always a template composing these; no provider name appears in Go.
	validFormats   = set("json", "kv-lines")
	validExpiryFmt = set("rfc3339", "unix")
	validMatchers  = set("", "pem-private-key")
	// Risk levels are the POLICY engine's vocabulary, so they are taken from it
	// rather than restated here. Restating them had already drifted: templates
	// could declare only low/medium/high while the engine ranks a fourth level,
	// critical — so a template-discovered credential could never be classified
	// critical, and therefore could never match a `min_risk: critical` rule,
	// while the Go scanners were storing AWS credentials at exactly that level.
	// Template-discovered credentials were structurally less protectable than
	// Go-discovered ones. Deriving the set makes that drift impossible.
	validRisks = set(append([]string{""}, policy.RiskLevels()...)...)
	// Source backends are Go-owned primitives: each knows its allowlisted
	// binary (or HTTP client), required-env whitelist, and output parser. A
	// template selects one by name and supplies typed params — never a command.
	// Only backends that are actually IMPLEMENTED are listed, so a template that
	// names an unavailable backend fails at load, not surprisingly at runtime.
	// More backends (vault-kv, the cloud secret managers, http) are added here
	// as they are implemented. There is deliberately NO arbitrary-`exec` backend
	// — running a template-chosen command would defeat the data/code boundary.
	validBackends     = set("onepassword-cli")
	validResolveModes = set("", "on-demand", "import")
)

// safeName mirrors assume.safeName: names become file path components.
var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// deliverFileLiteral matches the literal (placeholder-stripped) part of a
// deliver file name: a single path component's charset. It permits the empty
// string so a name that is exactly "{instance}" is allowed.
var deliverFileLiteral = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)

// deliverNameSafe reports whether a file-deliver name renders to a single,
// non-traversing path component, so the written credential file cannot escape
// the session dir. {instance} — the only placeholder allowed in a deliver
// name — resolves to a safeName-validated profile, so only the literal text
// between placeholders can smuggle in a separator or a ".." escape; rejecting
// '/', '\' and '..' in the literal is therefore sufficient.
func deliverNameSafe(name string) bool {
	if strings.Contains(name, "/") || strings.Contains(name, `\`) || strings.Contains(name, "..") {
		return false
	}
	return deliverFileLiteral.MatchString(placeholder.ReplaceAllString(name, ""))
}

// envVarKey matches a POSIX-style environment variable name. Env keys become
// real variables on the agent's process, so they are held to the shell's own
// identifier rules — no '=', separators, or control characters that would
// corrupt the child environment.
var envVarKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Template is one parsed artifact (provider or discovery).
type Template struct {
	Kind       string           `yaml:"kind"`
	Name       string           `yaml:"name"`
	Version    int              `yaml:"version"`
	Credential CredentialSpec   `yaml:"credential"`
	Discover   []DiscoverSource `yaml:"discover"`
	Source     []SourceSpec     `yaml:"source"`
	Deliver    []DeliverMode    `yaml:"deliver"`
	Agent      *AgentSpec       `yaml:"agent"`

	// Provider is set on kind:discovery artifacts — the provider template
	// whose credential shape the discovered values map onto.
	Provider string `yaml:"provider"`

	// origin is the file path this template was loaded from (empty for
	// hand-built values in tests). Replaces the old "builtin" bit: provenance
	// is where a template came from, not whether it was compiled in.
	origin string

	// digest is the hex SHA-256 of the exact bytes this struct was parsed from.
	// The trust gate must judge the structure it is about to act on, not
	// whatever the file holds at check time — those are different bytes the
	// moment anyone with write access swaps the file between load and check.
	digest string
}

// CredentialSpec declares what a secret of this provider consists of.
type CredentialSpec struct {
	Fields map[string]FieldSpec `yaml:"fields"`
}

// FieldSpec describes one credential field. Aliases are alternate keys the
// stored credential map may use for the same value (e.g. single-value labels
// store under "value"); the declared field name always wins when both exist.
type FieldSpec struct {
	Secret    bool     `yaml:"secret"`
	Optional  bool     `yaml:"optional"`
	Multiline bool     `yaml:"multiline"`
	Aliases   []string `yaml:"aliases"`
}

// SourceSpec fetches a credential from an external secrets manager (1Password,
// Vault, a cloud secrets manager, a REST API). Unlike discover (which reads
// local files), a source RUNS a named backend primitive — so it is a high-trust
// effect (CapRunBackend) and the backend, its binary, and its argv are owned by
// Go: the template supplies only typed parameters, never a command.
//
//	mode "on-demand": resolve per use, never stored (broker — preferred)
//	mode "import":    resolve once, vault locally
type SourceSpec struct {
	Backend string            `yaml:"backend"` // enum primitive (validBackends)
	Mode    string            `yaml:"mode"`    // on-demand | import (default on-demand)
	Ref     string            `yaml:"ref"`     // backend reference, e.g. "op://Vault/item/field"
	Params  map[string]string `yaml:"params"`  // typed backend parameters
	Map     map[string]string `yaml:"map"`     // backend output key -> credential field
	Cache   *CacheSpec        `yaml:"cache"`   // in-memory cache bound (≤ deliver TTL)
}

// CacheSpec bounds how long a resolved secret may be held in memory (never on
// disk) before re-resolving from the backend.
type CacheSpec struct {
	TTL int `yaml:"ttl"` // seconds
}

// DiscoverSource is one place instances of this credential may live.
type DiscoverSource struct {
	Source    string            `yaml:"source"`    // parser primitive: ini|json|yaml|file|env-lines
	Path      string            `yaml:"path"`      // location (~ allowed, glob allowed for source:file)
	Instances string            `yaml:"instances"` // naming: sections|keys|filename|single
	Match     string            `yaml:"match"`     // classifier or regex name (source:file / env-lines)
	Map       map[string]string `yaml:"map"`       // credential field -> key in the source
	Risk      string            `yaml:"risk"`
}

// DeliverMode is one way the credential can be handed to a consumer, listed
// best-first: helper/socket are on-demand (every access is a daemon round
// trip), file is materialized with a TTL, env is materialized uncontrolled.
type DeliverMode struct {
	Mode     string                 `yaml:"mode"`
	Contract string                 `yaml:"contract"` // describe: identity derivation primitive
	Format   string                 `yaml:"format"`   // helper wire format: json | kv-lines
	Map      map[string]string      `yaml:"map"`      // helper output key -> credential field
	Static   map[string]interface{} `yaml:"static"`   // helper literal outputs (scalars only)
	Expiry   *ExpirySpec            `yaml:"expiry"`   // helper output key receiving now+ttl
	Name     string                 `yaml:"name"`     // file name template ({instance})
	Render   []RenderLine           `yaml:"render"`   // file body, line by line
	Env      map[string]string      `yaml:"env"`      // env vars to set ({path}, {instance}, fields)
}

// ExpirySpec names the helper output key that carries the TTL deadline. This
// is what forces the consumer (AWS SDK, git) to call back — and re-audit —
// instead of caching the credential forever.
type ExpirySpec struct {
	Key    string `yaml:"key"`
	Format string `yaml:"format"` // rfc3339 | unix
}

// RenderLine is one line of a rendered credential file. A plain YAML string
// is an unconditional line; the object form {line: ..., if_set: field} emits
// the line only when the named optional field has a value. Presence checks
// are the only conditionality templates get.
type RenderLine struct {
	Line  string `yaml:"line"`
	IfSet string `yaml:"if_set"`
}

// UnmarshalYAML accepts either a bare string or the {line, if_set} object.
func (r *RenderLine) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		r.Line = s
		return nil
	}
	type raw RenderLine // avoid recursion
	var o raw
	if err := unmarshal(&o); err != nil {
		return err
	}
	*r = RenderLine(o)
	return nil
}

// AgentSpec is the env-ownership wiring: a list of ownership directives, each
// routing an agent's tooling through the daemon.
//
// SECURITY: a template never supplies a command. The config Akasha writes can
// make a downstream tool EXECUTE a callback (AWS credential_process, git's
// `helper = !cmd`), so if the command were template text a trusted-but-malicious
// template could write `credential_process = /bin/sh -c evil` → RCE. Instead the
// template selects a named PROTOCOL renderer (mechanism) and supplies only
// charset-validated structural params (a section name, a host). The renderer
// lives in Go and the only command it ever emits is the akasha binary
// (`<binary> helper <provider> --instance <instance>`). There is no slot for a
// command, so there is nothing to inject. This is parameterization (prepared
// statements), not sanitization — and the mechanism set is bounded by the few
// credential-callback PROTOCOLS that exist, never per provider.
type AgentSpec struct {
	Own []OwnDirective `yaml:"own"`
}

// Ownership mechanisms: callback PROTOCOL renderers, not service integrations.
// git-credential-helper is reused by github, gitlab, gitea, … with no new Go,
// exactly as kv-lines is reused by every line-protocol provider.
const (
	// MechCredentialProcess: an ini file whose `credential_process` key names
	// the akasha helper. AWS and any tool that speaks AWS's external-credential
	// protocol.
	MechCredentialProcess = "credential-process"
	// MechGitCredentialHelper: a gitconfig that host-scopes git's credential
	// helper to the akasha helper. Every git host.
	MechGitCredentialHelper = "git-credential-helper"
	// MechDecoy: plant an empty file at a tool's default credential path so the
	// plaintext path is dead (e.g. AWS_SHARED_CREDENTIALS_FILE).
	MechDecoy = "decoy"
)

var validMechanisms = set(MechCredentialProcess, MechGitCredentialHelper, MechDecoy)

// OwnDirective is one ownership action. Env names the session variable to inject
// (always a path into the agent dir). File is the generated filename. The
// remaining fields are mechanism-specific, charset-validated, structural params
// — never a command.
type OwnDirective struct {
	Mechanism string `yaml:"mechanism"`
	Env       string `yaml:"env"`  // session env var to inject
	File      string `yaml:"file"` // generated filename in the agent dir

	// credential-process: the ini section name (may use {instance}).
	Section string `yaml:"section"`

	// git-credential-helper: the host to scope the helper to, and whether to
	// re-include the user's real ~/.gitconfig (so identity/aliases survive).
	Host    string `yaml:"host"`
	Inherit bool   `yaml:"inherit_user_gitconfig"`
}

// envVarName and these param charsets are the allowlist that closes second-order
// (config-structure) injection: a param can't carry a newline or a bracket to
// break out of an ini section or gitconfig block.
var (
	envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// hostLitOK matches the literal remainder once {instance} is stripped, so it
	// must accept the empty string: `host: "{instance}"` is the whole value.
	hostLitOK    = regexp.MustCompile(`^[A-Za-z0-9.-]*$`)
	sectionLitOK = regexp.MustCompile(`^[A-Za-z0-9 ._/{}-]*$`) // section literal minus its {instance} placeholder
)

// DescribeDeliver returns the first mode:describe deliver entry, or nil.
//
// describe is the DESCRIBE mode: it hands a consumer non-secret FACTS about the
// credential (which account, what kind of key) rather than the credential
// itself. It lives in the deliver block because it is a way the credential
// answers a consumer — the same place helper and socket already live, both of
// which also hand over something derived rather than the stored secret.
//
// It is deliberately NOT a new top-level block: the core is frozen, so new
// capability arrives as a new named primitive selected from an existing block
// (see docs/PLUGIN_FORMAT.md, "The stability & extension contract").
func (t *Template) DescribeDeliver() *DeliverMode { return t.deliver("describe") }

// FileDeliver returns the first mode:file deliver entry, or nil.
func (t *Template) FileDeliver() *DeliverMode { return t.deliver("file") }

// EnvDeliver returns the first mode:env deliver entry, or nil.
func (t *Template) EnvDeliver() *DeliverMode { return t.deliver("env") }

// Delivers reports whether the template materializes a credential into a
// session — a file in the session dir and/or environment variables. This is
// the effect the trust gate protects: an assumable template must be approved
// before Akasha will apply it.
func (t *Template) Delivers() bool {
	return t.FileDeliver() != nil || t.EnvDeliver() != nil
}

// DeliversSecretEnv reports whether any deliver mode sets an environment
// variable whose value materializes a SECRET credential field (e.g. github's
// `GITHUB_TOKEN: {token}`). That env value IS the raw secret, so returning it to
// an agent defeats "the agent never sees the raw secret" — file-delivered
// providers instead set env vars to a file *path*, which is safe.
func (t *Template) DeliversSecretEnv() bool {
	for i := range t.Deliver {
		for _, val := range t.Deliver[i].Env {
			for _, m := range placeholder.FindAllStringSubmatch(val, -1) {
				if t.fieldIsSecret(m[1]) {
					return true
				}
			}
		}
	}
	return false
}

// fieldIsSecret reports whether name is a credential field (or alias) the
// template marks secret.
func (t *Template) fieldIsSecret(name string) bool {
	for f, spec := range t.Credential.Fields {
		if !spec.Secret {
			continue
		}
		if f == name {
			return true
		}
		for _, a := range spec.Aliases {
			if a == name {
				return true
			}
		}
	}
	return false
}

func (t *Template) deliver(mode string) *DeliverMode {
	for i := range t.Deliver {
		if t.Deliver[i].Mode == mode {
			return &t.Deliver[i]
		}
	}
	return nil
}

// Origin reports the file path this template was loaded from (empty for
// hand-built templates in tests).
func (t *Template) Origin() string { return t.origin }

// Digest reports the hex SHA-256 of the bytes this template was parsed from
// (empty for hand-built templates in tests).
func (t *Template) Digest() string { return t.digest }

// Capability constants name the high-trust effects a template can have. They
// are what the trust gate requires explicit, hash-bound human approval for.
const (
	// CapOwnAgentEnv: the template's agent block injects env vars and config
	// files into IDE/agent session settings on `akasha setup`, silently
	// rerouting that agent's tooling (e.g. git, aws) through the daemon. High
	// impact and applied without an explicit per-use action, so it gates.
	CapOwnAgentEnv = "own-agent-env"

	// CapRunBackend: the template has a source block, so resolving its
	// credential runs a backend (a subprocess or network call). Running code on
	// the user's behalf is the highest-trust effect, so it gates.
	CapRunBackend = "run-backend"

	// CapReadFiles: the template has a discover block, so it reads the file
	// paths it names off disk. Reading arbitrary user files (e.g. SSH keys) is
	// sensitive, so an untrusted discovery template is not run.
	CapReadFiles = "read-files"

	// CapDeliver: the template delivers credentials into an agent session — a
	// file in the session dir and/or environment variables. Delivery is what a
	// provider template exists to do, so a NEW one must be trusted before it
	// runs. Env values can execute code (a template legitimately sets
	// GIT_SSH_COMMAND to a command, so a malicious one sets PATH / LD_PRELOAD /
	// BASH_ENV just as easily and no validation tells them apart), and a file's
	// contents are attacker-chosen too — so any assumable template gates. It is
	// trusted once (hash-bound), then applies passively until its file changes.
	// File-name containment (deliverNameSafe) is defence-in-depth, not a
	// substitute for that trust.
	CapDeliver = "deliver"
)

// SensitiveCapabilities lists the effects that require explicit approval before
// Akasha will apply them. Any template that delivers a credential into a session
// is listed: a new provider must be trusted before it runs, uniformly, whether
// it delivers a file, environment variables, or both.
func (t *Template) SensitiveCapabilities() []string {
	var caps []string
	if t.Agent != nil {
		caps = append(caps, CapOwnAgentEnv)
	}
	if len(t.Source) > 0 {
		caps = append(caps, CapRunBackend)
	}
	if len(t.Discover) > 0 {
		caps = append(caps, CapReadFiles)
	}
	if t.Delivers() {
		caps = append(caps, CapDeliver)
	}
	return caps
}

// Capabilities summarizes what the template can DO, for the one-line load
// log: a discovery rule only reads, a provider with deliver/agent blocks
// writes files and environment into agent sessions.
func (t *Template) Capabilities() string {
	if t.Kind == KindDiscovery {
		return "read-only (discovery)"
	}
	caps := ""
	if len(t.Discover) > 0 {
		caps += " reads:" + fmt.Sprint(len(t.Discover)) + "-locations"
	}
	for _, s := range t.Source {
		caps += " runs:" + s.Backend
	}
	for _, d := range t.Deliver {
		// describe is the one deliver mode that writes nothing — it hands back
		// derived facts, never the credential — so calling it a write would
		// overstate it in the one line most people read.
		if d.Mode == "describe" {
			caps += " describes:" + d.Contract
			continue
		}
		caps += " writes:" + d.Mode
	}
	if t.Agent != nil {
		caps += " writes:agent-env"
	}
	if caps == "" {
		return "inert"
	}
	return caps[1:]
}

// Degradation records one capability a template declared that this daemon does
// not implement, and which was therefore dropped rather than taken as a reason
// to reject the whole file.
//
// The distinction this enables is the point. The format's core is frozen but
// its primitive registry grows, so a bundle from a newer release routinely
// names primitives an older daemon has never heard of. Rejecting the file for
// that took a provider out entirely — a template adding one new deliver mode
// lost `assume`, its credential helper, and `exec --assume` along with it.
// Dropping just the unrecognised capability keeps everything the daemon does
// understand working.
type Degradation struct {
	Where  string // "deliver[1]", "mint", "discover[0]"
	Reason string
}

func (d Degradation) String() string { return d.Where + ": " + d.Reason }

// degradeCtx carries whether unknown capability names are fatal, and collects
// what was dropped when they are not.
//
// Two callers, two answers. Authoring tools (`akasha template validate`) are
// strict: a plugin author typing `mode: fille` must be told, not quietly given
// a template that does nothing. The daemon's load path is lenient: it is
// reading a file it may not be new enough to fully understand, and a partial
// provider beats no provider.
type degradeCtx struct {
	strict bool
	found  []Degradation
}

// drop reports an unrecognised capability name: an error in strict mode, a
// recorded degradation otherwise.
//
// It is ONLY for unknown names. A malformed known primitive — a traversing file
// name, an ini-breaking section, a missing required sub-field — stays fatal on
// both paths, because that is a bug or an attack rather than a daemon that is
// behind. Everything reached through this function is a capability whose
// absence removes a feature; nothing reached through it changes containment.
func (dc *degradeCtx) drop(where, format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	if dc.strict {
		return fmt.Errorf("%s: %s", where, reason)
	}
	dc.found = append(dc.found, Degradation{Where: where, Reason: reason})
	return nil
}

// Validate checks the template against the schema rules, strictly: an
// unrecognised capability name is an error. This is the authoring contract —
// `akasha template validate` and hand-built templates in tests.
//
// The daemon loads through ParseLenient instead, which degrades unknown
// capabilities rather than rejecting the file.
func (t *Template) Validate() error { return t.validate(&degradeCtx{strict: true}) }

// validate is Validate's implementation, parameterized by how unknown
// capability names are handled.
func (t *Template) validate(dc *degradeCtx) error {
	if t.Name == "" || !safeName.MatchString(t.Name) || t.Name == "." || t.Name == ".." {
		return fmt.Errorf("template name %q: only letters, digits, '.', '_', '-' allowed", t.Name)
	}
	if t.Version != 1 {
		return fmt.Errorf("template %s: unsupported version %d (want 1)", t.Name, t.Version)
	}
	switch t.Kind {
	case KindProvider:
		return t.validateProvider(dc)
	case KindDiscovery:
		return t.validateDiscovery(dc)
	default:
		// kind is structural, not a capability: an unknown kind means the
		// document's shape is unknown, so there is nothing safe to keep.
		return fmt.Errorf("template %s: unknown kind %q (want %q or %q)", t.Name, t.Kind, KindProvider, KindDiscovery)
	}
}

func (t *Template) validateProvider(dc *degradeCtx) error {
	if t.Provider != "" {
		return fmt.Errorf("template %s: 'provider:' is only valid on kind: discovery", t.Name)
	}
	if len(t.Credential.Fields) == 0 {
		return fmt.Errorf("template %s: credential.fields must not be empty", t.Name)
	}
	if len(t.Deliver) == 0 {
		return fmt.Errorf("template %s: at least one deliver mode is required", t.Name)
	}

	// fieldVars: placeholders resolvable from the credential map.
	fieldVars := map[string]bool{"instance": true}
	for f, spec := range t.Credential.Fields {
		if !safeName.MatchString(f) {
			return fmt.Errorf("template %s: invalid field name %q", t.Name, f)
		}
		fieldVars[f] = true
		for _, a := range spec.Aliases {
			if !safeName.MatchString(a) {
				return fmt.Errorf("template %s field %s: invalid alias %q", t.Name, f, a)
			}
			if t.hasField(a) {
				return fmt.Errorf("template %s field %s: alias %q collides with a declared field", t.Name, f, a)
			}
		}
	}

	if err := t.validateDiscover(dc, fieldVars); err != nil {
		return err
	}

	// Source backends are NOT degradable. credsFor takes the vault path when
	// len(tpl.Source) == 0, so dropping an unknown backend would silently serve
	// a stale local copy of a credential the template says must come live from
	// an upstream manager. Failing the file is the safe answer.
	if err := t.validateSource(fieldVars); err != nil {
		return err
	}

	kept := make([]DeliverMode, 0, len(t.Deliver))
	for i, d := range t.Deliver {
		where := fmt.Sprintf("template %s deliver[%d]", t.Name, i)
		if !validModes[d.Mode] {
			if err := dc.drop(where, "unknown mode %q", d.Mode); err != nil {
				return err
			}
			continue
		}
		// Each mode's own primitive name is checked before its structural
		// rules, so an unknown name degrades while a malformed known mode
		// still fails.
		switch d.Mode {
		case "helper":
			if !validFormats[d.Format] {
				if err := dc.drop(where, "unknown helper format %q (this daemon knows: %s)", d.Format, joinSet(validFormats)); err != nil {
					return err
				}
				continue
			}
			if err := t.validateHelper(&d, where); err != nil {
				return err
			}
		case "describe":
			// The contract is a Go-owned derivation selected by name; the map is
			// the template's DISCLOSURE LIST, deciding which of the facts that
			// contract can compute are actually revealed. Both are checked here
			// so a template that names a nonexistent contract, or asks to reveal
			// a fact nothing can produce, fails at load rather than at use.
			if !identity.Known(d.Contract) {
				if err := dc.drop(where, "unknown identity contract %q (this daemon knows: %s)",
					d.Contract, strings.Join(identity.Names(), ", ")); err != nil {
					return err
				}
				continue
			}
			if len(d.Map) == 0 {
				return fmt.Errorf("%s: describe mode needs a map naming which facts to reveal (a contract discloses nothing by default)", where)
			}
			producible, err := identity.Produces(d.Contract)
			if err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
			// A disclosure list naming a fact this daemon's build of the
			// contract cannot compute is the same version skew one level down:
			// a newer contract produces more. Drop those entries and keep the
			// rest, so a template asking for two facts still gets the one this
			// daemon can derive.
			revealed := make(map[string]string, len(d.Map))
			for out, fact := range d.Map {
				if !slices.Contains(producible, fact) {
					if err := dc.drop(where, "map %s -> %q, which contract %q cannot produce here (it produces: %s)",
						out, fact, d.Contract, strings.Join(producible, ", ")); err != nil {
						return err
					}
					continue
				}
				revealed[out] = fact
			}
			if len(revealed) == 0 {
				if err := dc.drop(where, "no requested fact can be produced by contract %q here", d.Contract); err != nil {
					return err
				}
				continue
			}
			d.Map = revealed
			// describe reveals derived facts, never credential fields, so the
			// secret-bearing parts of a deliver mode must be absent.
			if len(d.Env) > 0 || len(d.Render) > 0 || d.Name != "" {
				return fmt.Errorf("%s: describe mode reveals derived facts only — it cannot set env, render a file, or name one", where)
			}
		case "file":
			if d.Name == "" {
				return fmt.Errorf("%s: file mode needs a name", where)
			}
			if err := checkVars(d.Name, map[string]bool{"instance": true}); err != nil {
				return fmt.Errorf("%s name: %w", where, err)
			}
			if !deliverNameSafe(d.Name) {
				return fmt.Errorf("%s: file name %q must be a single filename with no '/', '\\' or '..' — it is written into the session dir", where, d.Name)
			}
			if len(d.Render) == 0 {
				return fmt.Errorf("%s: file mode needs render lines", where)
			}
			for _, l := range d.Render {
				if err := checkVars(l.Line, fieldVars); err != nil {
					return fmt.Errorf("%s render: %w", where, err)
				}
				if l.IfSet != "" && !t.hasField(l.IfSet) {
					return fmt.Errorf("%s render: if_set references unknown field %q", where, l.IfSet)
				}
			}
			fallthrough
		case "env":
			vars := map[string]bool{"path": true}
			for v := range fieldVars {
				vars[v] = true
			}
			for k, val := range d.Env {
				if !envVarKey.MatchString(k) {
					return fmt.Errorf("%s: invalid env var name %q (must match [A-Za-z_][A-Za-z0-9_]*)", where, k)
				}
				if err := checkVars(val, vars); err != nil {
					return fmt.Errorf("%s env %s: %w", where, k, err)
				}
			}
			if d.Mode == "env" && len(d.Env) == 0 {
				return fmt.Errorf("%s: env mode needs env entries", where)
			}
		}
		kept = append(kept, d)
	}
	// A provider may end up with no usable deliver mode — every route it
	// declares is newer than this daemon. It still loads: discovery and
	// vaulting work, `list` shows it, and only assume fails, with an error that
	// names the gap. That is far more diagnosable than the provider silently
	// not existing.
	t.Deliver = kept

	// Agent ownership is NOT degradable. MechDecoy is what points
	// AWS_SHARED_CREDENTIALS_FILE at an empty file so an agent cannot read the
	// human's real credentials; silently dropping an unrecognised mechanism
	// would remove containment and leave everything looking fine. An unknown
	// mechanism means this daemon cannot honour the template's isolation
	// contract, so it must refuse the file.
	if t.Agent != nil {
		if err := t.validateOwn(); err != nil {
			return err
		}
	}

	return nil
}

// validateHelper checks a helper deliver mode at load time so a bad template
// fails on load, never mid-resolve. Beyond schema shape, this is a security
// boundary: helper output is a wire protocol consumed by provider tooling, so
// everything that could corrupt framing is rejected here — kv-lines keys are
// charset-bound, multiline credential fields cannot be mapped onto a
// line-oriented format, and static values must be flat scalars.
func (t *Template) validateHelper(d *DeliverMode, where string) error {
	if d.Contract != "" {
		return fmt.Errorf("%s: helper mode takes 'format', not 'contract' (contracts are socket-only)", where)
	}
	if !validFormats[d.Format] {
		return fmt.Errorf("%s: unknown format %q (want json or kv-lines)", where, d.Format)
	}
	if len(d.Map) == 0 && len(d.Static) == 0 {
		return fmt.Errorf("%s: helper mode emits nothing (need map or static entries)", where)
	}

	seen := map[string]bool{}
	checkKey := func(k, src string) error {
		if k == "" {
			return fmt.Errorf("%s: empty %s key", where, src)
		}
		// kv-lines keys become `key=value` protocol lines: bind them to a safe
		// charset so a key can never smuggle '=', whitespace, or a newline.
		if d.Format == "kv-lines" && !safeName.MatchString(k) {
			return fmt.Errorf("%s: %s key %q: only letters, digits, '.', '_', '-' allowed in kv-lines", where, src, k)
		}
		if seen[k] {
			return fmt.Errorf("%s: duplicate output key %q", where, k)
		}
		seen[k] = true
		return nil
	}

	for out, field := range d.Map {
		if err := checkKey(out, "map"); err != nil {
			return err
		}
		if !t.hasField(field) {
			return fmt.Errorf("%s: map %s -> unknown field %q", where, out, field)
		}
		if d.Format == "kv-lines" && t.Credential.Fields[field].Multiline {
			return fmt.Errorf("%s: map %s -> field %q is multiline, which a line-oriented format cannot carry", where, out, field)
		}
	}
	for k, v := range d.Static {
		if err := checkKey(k, "static"); err != nil {
			return err
		}
		switch sv := v.(type) {
		case string:
			if d.Format == "kv-lines" && strings.ContainsAny(sv, "\n\r\x00") {
				return fmt.Errorf("%s: static %s contains line-control characters", where, k)
			}
		case int, int64, uint64, float64, bool:
			// flat scalars are fine
		default:
			return fmt.Errorf("%s: static %s must be a flat scalar (string/number/bool), got %T", where, k, v)
		}
	}
	if d.Expiry != nil {
		if err := checkKey(d.Expiry.Key, "expiry"); err != nil {
			return err
		}
		if !validExpiryFmt[d.Expiry.Format] {
			return fmt.Errorf("%s: expiry format %q (want rfc3339 or unix)", where, d.Expiry.Format)
		}
	}
	return nil
}

func (t *Template) validateDiscovery(dc *degradeCtx) error {
	if t.Provider == "" {
		return fmt.Errorf("template %s: kind discovery requires 'provider:'", t.Name)
	}
	if len(t.Deliver) > 0 || t.Agent != nil || len(t.Credential.Fields) > 0 {
		return fmt.Errorf("template %s: kind discovery may only contain discover rules", t.Name)
	}
	if len(t.Discover) == 0 {
		return fmt.Errorf("template %s: discovery rule has no discover sources", t.Name)
	}
	return t.validateDiscover(dc, nil)
}

// validateOwn checks each ownership directive. Crucially there is NO command
// field to validate — the command is Go-rendered. We allowlist-validate the
// structural params (env var name, file name, ini section, host) so a param
// can't break out of the config structure (second-order injection).
func (t *Template) validateOwn() error {
	if len(t.Agent.Own) == 0 {
		return fmt.Errorf("template %s agent: at least one own directive is required", t.Name)
	}
	for i, d := range t.Agent.Own {
		where := fmt.Sprintf("template %s agent.own[%d]", t.Name, i)
		if !validMechanisms[d.Mechanism] {
			return fmt.Errorf("%s: unknown mechanism %q", where, d.Mechanism)
		}
		if !envVarName.MatchString(d.Env) {
			return fmt.Errorf("%s: invalid env var name %q", where, d.Env)
		}
		if d.File == "" || !safeName.MatchString(d.File) {
			return fmt.Errorf("%s: invalid file name %q", where, d.File)
		}
		switch d.Mechanism {
		case MechCredentialProcess:
			if d.Section == "" {
				return fmt.Errorf("%s: credential-process needs a section", where)
			}
			// {instance} is the only placeholder; the literal remainder must be
			// ini-safe (no brackets/newlines that could inject a directive).
			if err := checkVars(d.Section, map[string]bool{"instance": true}); err != nil {
				return fmt.Errorf("%s section: %w", where, err)
			}
			if !sectionLitOK.MatchString(placeholder.ReplaceAllString(d.Section, "")) {
				return fmt.Errorf("%s: section %q has characters that could break the ini structure", where, d.Section)
			}
		case MechGitCredentialHelper:
			if d.Host == "" {
				return fmt.Errorf("%s: git-credential-helper needs a host", where)
			}
			// {instance} is the only placeholder, so one directive can host-scope
			// every discovered instance — a provider whose instances ARE hostnames
			// (git's credential store keys by host) needs no per-host template.
			// The literal remainder must still be hostname-safe: the value lands
			// in a `[credential "https://<host>"]` section label.
			if err := checkVars(d.Host, map[string]bool{"instance": true}); err != nil {
				return fmt.Errorf("%s host: %w", where, err)
			}
			if !hostLitOK.MatchString(placeholder.ReplaceAllString(d.Host, "")) {
				return fmt.Errorf("%s: invalid host %q (hostname chars only)", where, d.Host)
			}
		case MechDecoy:
			// No structural params; an empty file is planted at d.File.
		}
	}
	return nil
}

// validateSource checks each source block: a known backend and mode, a non-empty
// ref whose placeholders resolve to {instance} or a declared param, and a map
// onto declared credential fields. Backend-specific param schemas are enforced
// by the resolver engine (Go), keeping this to the shape the format guarantees.
func (t *Template) validateSource(fieldVars map[string]bool) error {
	for i, s := range t.Source {
		where := fmt.Sprintf("template %s source[%d]", t.Name, i)
		if !validBackends[s.Backend] {
			return fmt.Errorf("%s: unknown backend %q", where, s.Backend)
		}
		if !validResolveModes[s.Mode] {
			return fmt.Errorf("%s: unknown mode %q (want on-demand or import)", where, s.Mode)
		}
		if s.Ref == "" {
			return fmt.Errorf("%s: ref is required", where)
		}
		// ref/params may reference {instance} and any declared param key.
		refVars := map[string]bool{"instance": true}
		for k := range s.Params {
			if !safeName.MatchString(k) {
				return fmt.Errorf("%s: invalid param name %q", where, k)
			}
			refVars[k] = true
		}
		if err := checkVars(s.Ref, refVars); err != nil {
			return fmt.Errorf("%s ref: %w", where, err)
		}
		if len(s.Map) == 0 {
			return fmt.Errorf("%s: map must bind at least one backend output to a credential field", where)
		}
		for out, field := range s.Map {
			if out == "" {
				return fmt.Errorf("%s: empty map key", where)
			}
			if !t.hasField(field) {
				return fmt.Errorf("%s: map %s -> unknown field %q", where, out, field)
			}
		}
		if s.Cache != nil && s.Cache.TTL < 0 {
			return fmt.Errorf("%s: cache ttl must be ≥ 0", where)
		}
	}
	return nil
}

// validateDiscover checks each discovery rule. A rule naming a parser,
// instance-naming scheme, or matcher this daemon does not implement is dropped:
// the provider keeps the rules it CAN run, so a bundle that adds a new parser
// does not cost you discovery of the locations that already worked.
//
// Risk is not degradable — it is a classification the policy engine ranks, not
// a capability, and an unrankable risk would put an entry out of reach of every
// min_risk rule (the same hole ValidRisk exists to close on the ingest side).
func (t *Template) validateDiscover(dc *degradeCtx, fieldVars map[string]bool) error {
	kept := make([]DiscoverSource, 0, len(t.Discover))
	for i, d := range t.Discover {
		where := fmt.Sprintf("template %s discover[%d]", t.Name, i)
		if !validSources[d.Source] {
			if err := dc.drop(where, "unknown source %q (this daemon knows: %s)", d.Source, joinSet(validSources)); err != nil {
				return err
			}
			continue
		}
		if d.Instances != "" && !validInstances[d.Instances] {
			if err := dc.drop(where, "unknown instances %q (this daemon knows: %s)", d.Instances, joinSet(validInstances)); err != nil {
				return err
			}
			continue
		}
		if !validMatchers[d.Match] {
			if err := dc.drop(where, "unknown matcher %q (this daemon knows: %s)", d.Match, joinSet(validMatchers)); err != nil {
				return err
			}
			continue
		}
		// Every source reads a file except `env`, which reads this process's
		// environment and so has nothing to name.
		if d.Path == "" && d.Source != "env" {
			return fmt.Errorf("%s: path is required", where)
		}
		if d.Path != "" && d.Source == "env" {
			return fmt.Errorf("%s: env source reads the process environment and takes no path", where)
		}
		if !validRisks[d.Risk] {
			return fmt.Errorf("%s: unknown risk %q", where, d.Risk)
		}
		if fieldVars != nil {
			for field := range d.Map {
				if !fieldVars[field] || field == "instance" {
					return fmt.Errorf("%s: map references unknown field %q", where, field)
				}
			}
		}
		kept = append(kept, d)
	}
	t.Discover = kept
	return nil
}

// joinSet renders an enum registry for an error message, sorted so the same
// mistake always reads the same way.
func joinSet(m map[string]bool) string {
	names := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func (t *Template) hasField(name string) bool {
	_, ok := t.Credential.Fields[name]
	return ok
}

// ResolveCreds normalizes a stored credential map against the template's
// declared fields: aliases resolve to their field name, undeclared keys are
// dropped, and a missing non-optional field is an error. The result is keyed
// purely by declared field names, so render/helper code never sees aliases.
// CanonicalField maps a key a caller used to the field name this template
// DECLARES, resolving aliases. Unknown keys come back unchanged.
//
// Anything that judges a field by its name has to canonicalise first or it
// judges the wrong thing. github, gitlab and git all declare
// `token: {aliases: [value]}`, and ssh declares the same for private_key — so a
// caller writing {"value": "..."} reached a shape check that had an opinion
// about `token`, found none for `value`, and passed. ResolveCreds then mapped
// value → token anyway and the label was re-pointed. One word walked past the
// guard.
func (t *Template) CanonicalField(key string) string {
	if t == nil {
		return key
	}
	if _, declared := t.Credential.Fields[key]; declared {
		return key
	}
	for field, spec := range t.Credential.Fields {
		for _, a := range spec.Aliases {
			if a == key {
				return field
			}
		}
	}
	return key
}

func (t *Template) ResolveCreds(creds map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(t.Credential.Fields))
	// Sorted, because Credential.Fields is a map and ranging it directly made
	// the ERROR depend on Go's randomised iteration order: the same rejected
	// map named access_key_id on one run and secret_access_key on the next.
	// That reads as two different problems to whoever is trying to fix one, and
	// it made a test asserting on the message flaky in CI.
	names := make([]string, 0, len(t.Credential.Fields))
	for f := range t.Credential.Fields {
		names = append(names, f)
	}
	sort.Strings(names)

	for _, f := range names {
		spec := t.Credential.Fields[f]
		v := creds[f]
		for _, a := range spec.Aliases {
			if v != "" {
				break
			}
			v = creds[a]
		}
		if v == "" && !spec.Optional {
			return nil, fmt.Errorf("%s assume: missing required field %q", t.Name, f)
		}
		if v != "" {
			out[f] = v
		}
	}
	return out, nil
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}
