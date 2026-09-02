package vault

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CredentialSources lists the files this vault's credentials were discovered
// from, so the sandbox can mask exactly those.
//
// `akasha run` promises that "your plaintext credential files are unreachable"
// and masked a hand-written list of well-known locations: ~/.aws, ~/.ssh,
// ~/.netrc and the rest. But akasha's own templates declare sixteen places a
// credential can be found, and fourteen of them were not on that list — every
// shell startup file and every .env glob. Measured: an AWS key seeded into
// ~/.zshrc and ~/.env was flagged by `akasha discover` as a credential, and read
// straight out of both from inside the sandbox, with sha256 matching in and out.
//
// The obvious repair — mask everything the templates declare — is worse than the
// gap. Those globs cover ~/.env, ~/projects/.env*, ~/work/.env* and the shell
// files that set up PATH: masking them breaks the application the agent was
// launched to work on, and breaks the shell it works in. A sandbox that has to
// be turned off to get anything done protects nothing.
//
// Provenance is the way out. Discovery already records where each credential
// came from, so the vault knows which of those files actually hold a secret on
// THIS machine. A .env with a vaulted credential in it is masked; a .env with
// application config in it is untouched. The list is derived rather than
// maintained, so a new template's discover block is covered the day it lands —
// the same reasoning that fixed the agent-key gap, applied to the other list.
//
// What this does NOT cover, stated because a sandbox whose gaps are unwritten
// cannot be audited: a credential that has never been discovered is not in the
// vault, so its file is not in this list. Masking is only ever as complete as
// discovery.
func (v *Vault) CredentialSources() ([]string, error) {
	profiles, err := v.ListProfiles("")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		raw := strings.TrimSpace(p.Metadata["source"])
		if raw == "" {
			continue
		}
		abs := expandSource(raw)
		if abs == "" {
			continue
		}
		seen[abs] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out) // deterministic, so two profiles render the same argv
	return out, nil
}

// expandSource turns a recorded source into an absolute path, or "" if it is
// not one.
//
// Discovery records what the template matched, which is a real path — but it is
// stored as text and displayed with ~ for brevity, so both spellings appear.
// Anything that is not an absolute path after expansion is dropped rather than
// guessed at: this list becomes mount arguments, and a relative or empty entry
// there is a mask on the wrong thing.
func expandSource(raw string) string {
	p := raw
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		p = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
	}
	if !filepath.IsAbs(p) {
		return ""
	}
	return filepath.Clean(p)
}
