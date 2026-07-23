package setup

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inferlabshq/akasha/internal/template"
)

// ownrender is the ONLY place an agent-ownership config is generated, and the
// ONLY command it ever emits is the akasha binary. A template selects a
// protocol mechanism and supplies charset-validated structural params; it can
// never supply a command, so there is nothing to inject. See template.AgentSpec.

// instanceSafe is a defence-in-depth guard: an instance name flows into the
// generated config (a section label and the helper's --instance arg), so reject
// anything that could break the config structure even though vault labels are
// already constrained upstream.
var instanceSafe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type ownResult struct {
	envName  string
	envValue string // absolute path into the agent dir
	path     string
	content  []byte
	write    bool // false → don't create the file yet (nothing vaulted)
}

// helperCommand builds the fixed callback: `<abs-akasha> helper <provider>
// --instance <instance>`. binary is supplied by setup (the akasha path), never
// by the template. provider is the template name (already charset-constrained).
func helperCommand(binary, provider, instance string) string {
	return fmt.Sprintf("%s helper %s --instance %s", binary, provider, instance)
}

func renderOwn(d template.OwnDirective, provider, binary, agentDir string, instances []string) ownResult {
	path := filepath.Join(agentDir, d.File)
	r := ownResult{envName: d.Env, envValue: path, path: path}

	safe := instances[:0:0]
	for _, inst := range instances {
		if instanceSafe.MatchString(inst) {
			safe = append(safe, inst)
		}
	}

	switch d.Mechanism {
	case template.MechDecoy:
		// Plant an empty file at the tool's default credential path so the
		// plaintext path returns nothing. Always written.
		r.content = []byte{}
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
		r.content = []byte(b.String())
		r.write = true

	case template.MechGitCredentialHelper:
		if len(safe) == 0 {
			return r
		}
		var b strings.Builder
		if d.Inherit {
			// Inherit the user's real gitconfig (identity/aliases) before we
			// override only the credential helper for this host.
			b.WriteString("[include]\n    path = ~/.gitconfig\n")
		}
		for _, inst := range safe {
			// The empty `helper =` resets any inherited helper for this host,
			// so a keychain-stored plaintext credential can't answer instead.
			fmt.Fprintf(&b, "[credential \"https://%s\"]\n    helper =\n    helper = !%s\n",
				d.Host, helperCommand(binary, provider, inst))
		}
		r.content = []byte(b.String())
		r.write = true
	}
	return r
}
