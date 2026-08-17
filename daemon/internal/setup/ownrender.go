package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// OwnInput is one provider's ownership directives plus its vaulted instances,
// the unit AssembleOwnership merges. Exported so `akasha exec` can build it.
type OwnInput struct {
	Provider  string
	Own       []template.OwnDirective
	Instances []string
}

// AssembleOwnership renders the agent.own directives of one or more providers
// into dir and returns the env vars that route each provider's tooling through
// akasha's per-operation broker. Directives that target the SAME env var are
// MERGED into a single config file — so github and gitlab both owning
// GIT_CONFIG_GLOBAL produce one gitconfig carrying both credential sections
// (with the [include] preamble once), instead of two files that collide on the
// env var. binary is the akasha path (never template-supplied); the only command
// ever emitted is that binary.
func AssembleOwnership(dir, binary string, inputs []OwnInput) (map[string]string, error) {
	// Render deterministically: sort providers so a merged file's section order
	// (and thus its bytes) doesn't depend on --assume order or map iteration.
	sorted := append([]OwnInput(nil), inputs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Provider < sorted[j].Provider })

	type group struct {
		anyPath   string          // some directive's default path (env pointer when nothing writes)
		writePath string          // a writing directive's default path (used when exactly one writes)
		writers   int             // directives that actually contribute content
		preambles []string        // distinct once-per-file preambles, in insertion order
		seenPre   map[string]bool // preamble dedup (github + gitlab share [include])
		bodies    [][]byte        // per-directive contributions, concatenated
	}
	groups := map[string]*group{}
	var order []string // env-var order, for a stable env map / file set

	for _, in := range sorted {
		for _, d := range in.Own {
			r := renderOwn(d, in.Provider, binary, dir, in.Instances)
			if r.envName == "" {
				continue
			}
			g := groups[r.envName]
			if g == nil {
				g = &group{seenPre: map[string]bool{}}
				groups[r.envName] = g
				order = append(order, r.envName)
			}
			g.anyPath = r.envValue
			if !r.write {
				continue // no vaulted instances yet — contributes nothing to the file
			}
			g.writers++
			g.writePath = r.envValue
			if len(r.preamble) > 0 && !g.seenPre[string(r.preamble)] {
				g.seenPre[string(r.preamble)] = true
				g.preambles = append(g.preambles, string(r.preamble))
			}
			if len(r.body) > 0 {
				g.bodies = append(g.bodies, r.body)
			}
		}
	}

	env := map[string]string{}
	for _, ev := range order {
		g := groups[ev]
		if g.writers == 0 {
			env[ev] = g.anyPath // nothing vaulted yet; env still points at the (future) file
			continue
		}
		// Keep the writer's own filename when it's the only one for this env var
		// (byte-identical to the pre-merge behaviour); use a canonical,
		// order-independent name when several providers merge into one file.
		path := g.writePath
		if g.writers > 1 {
			path = filepath.Join(dir, mergedFileName(ev))
		}
		env[ev] = path
		var content []byte
		for _, p := range g.preambles {
			content = append(content, p...)
		}
		for _, body := range g.bodies {
			content = append(content, body...)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			return nil, fmt.Errorf("write ownership file %s: %w", path, err)
		}
	}
	return env, nil
}

// RenderOwnershipEnv applies ONE provider's agent.own directives into dir. It is
// a thin wrapper over AssembleOwnership for the single-provider callers (and the
// existing tests); `akasha exec` calls AssembleOwnership directly so it can merge
// several providers. Returns nil if tpl declares no agent block.
func RenderOwnershipEnv(tpl *template.Template, binary, dir string, instances []string) (map[string]string, error) {
	if tpl == nil || tpl.Agent == nil {
		return nil, nil
	}
	return AssembleOwnership(dir, binary, []OwnInput{{Provider: tpl.Name, Own: tpl.Agent.Own, Instances: instances}})
}

// mergedFileName is the deterministic filename for a config file several
// providers merge into. Keyed by the env var (which is charset-constrained
// upstream) so it is order-independent: GIT_CONFIG_GLOBAL → "git_config_global".
func mergedFileName(envVar string) string {
	return strings.ToLower(envVar)
}

// ownrender is the ONLY place an agent-ownership config is generated, and the
// ONLY command it ever emits is the akasha binary. A template selects a
// protocol mechanism and supplies charset-validated structural params; it can
// never supply a command, so there is nothing to inject. See template.AgentSpec.

// instanceSafe is a defence-in-depth guard: an instance name flows into the
// generated config (a section label and the helper's --instance arg), so reject
// anything that could break the config structure even though vault labels are
// already constrained upstream.
var instanceSafe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// hostSafe re-checks a git-credential-helper host AFTER {instance} substitution.
// The template loader validates the host literal, but an instance substituted
// into it is only constrained by instanceSafe, which is a wider charset than a
// hostname — and the result becomes a gitconfig section label.
var hostSafe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// ownResult is one directive rendered into its parts: a preamble emitted once
// per (possibly merged) file, and a body concatenated per directive.
type ownResult struct {
	envName  string // session env var this directive targets — the merge key
	envValue string // default file path (agentDir/File); overridden when merged
	preamble []byte // once-per-file (e.g. git's [include]); deduped across a merge
	body     []byte // this directive's contribution, concatenated across a merge
	write    bool   // false → nothing vaulted yet (env still points at the path)
}

// helperCommand builds the fixed callback: `<abs-akasha> helper <provider>
// --instance <instance>`. binary is supplied by setup (the akasha path), never
// by the template. provider is the template name (already charset-constrained).
func helperCommand(binary, provider, instance string) string {
	return fmt.Sprintf("%s helper %s --instance %s", binary, provider, instance)
}

func renderOwn(d template.OwnDirective, provider, binary, agentDir string, instances []string) ownResult {
	r := ownResult{envName: d.Env, envValue: filepath.Join(agentDir, d.File)}

	safe := instances[:0:0]
	for _, inst := range instances {
		if instanceSafe.MatchString(inst) {
			safe = append(safe, inst)
		}
	}

	switch d.Mechanism {
	case template.MechDecoy:
		// Plant an empty file at the tool's default credential path so the
		// plaintext path returns nothing. Always written (no body).
		r.write = true

	case template.MechCredentialProcess:
		if len(safe) == 0 {
			return r // nothing vaulted yet; env points at the future file
		}
		var b strings.Builder
		for _, inst := range safe {
			section := strings.ReplaceAll(d.Section, "{instance}", inst)
			fmt.Fprintf(&b, "[%s]\ncredential_process = %s\n", section, helperCommand(binary, provider, inst))
		}
		r.body = []byte(b.String())
		r.write = true

	case template.MechGitCredentialHelper:
		if d.Inherit {
			// GIT_CONFIG_GLOBAL REPLACES ~/.gitconfig rather than adding to it,
			// so this file must exist and carry the include even with nothing
			// vaulted — otherwise the session has no user.name/user.email at
			// all. Once-per-file: on a merge, github and gitlab share this
			// single [include].
			r.preamble = []byte("[include]\n    path = ~/.gitconfig\n")
			r.write = true
		}
		if len(safe) == 0 {
			return r
		}
		var b strings.Builder
		for _, inst := range safe {
			host := strings.ReplaceAll(d.Host, "{instance}", inst)
			if !hostSafe.MatchString(host) {
				continue
			}
			// The empty `helper =` resets any inherited helper for this host,
			// so a keychain-stored plaintext credential can't answer instead.
			fmt.Fprintf(&b, "[credential \"https://%s\"]\n    helper =\n    helper = !%s\n",
				host, helperCommand(binary, provider, inst))
		}
		r.body = []byte(b.String())
		r.write = true
	}
	return r
}
