package provision

import (
	"fmt"
	"sort"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Review renders "here is what was found on your machine" — the listing that
// has to be on screen before anything is written to the vault.
//
// It lives beside the vaulting plumbing, and not in the discover command, for
// the reason that plumbing does: `akasha setup` vaulted every finding with no
// listing and no question, so the consent UI existed only on the command a user
// reaches SECOND. The first-run path is the one that most needs it.
func Review(findings []template.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Found %d credential(s):\n\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(&b, "  [%d] %s:%s\n", i+1, f.Provider, f.Instance)
		fmt.Fprintf(&b, "      source: %s\n", f.Source)
		fmt.Fprintf(&b, "      fields: %s\n", describeFields(f.Fields))
		b.WriteString(describeShadowed(f))
		b.WriteByte('\n')
	}
	return b.String()
}

// describeFields summarises a finding without printing any secret: field names,
// and for each whether a value was actually found. Missing pieces are what the
// user needs to see — a credential half-discovered is the case worth noticing.
func describeFields(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// describeShadowed reports the copies of this credential that were found
// elsewhere and will NOT be vaulted.
//
// This is the only place the user can learn that a choice was made for them.
// Two rows reading "aws:default" with different sources look identical in the
// listing — describeFields prints field names, never values — so without this
// block there is nothing on screen to distinguish "the same key, found twice"
// from "two different keys, one of which is about to be discarded".
func describeShadowed(f template.Finding) string {
	if len(f.Shadowed) == 0 {
		return ""
	}
	var b strings.Builder
	for _, src := range f.Shadowed {
		fmt.Fprintf(&b, "      ! a DIFFERENT %s:%s was also found in %s — not vaulted\n", f.Provider, f.Instance, src)
	}
	fmt.Fprintf(&b, "        One credential can hold the name %s:%s, and the source listed\n", f.Provider, f.Instance)
	fmt.Fprintf(&b, "        first by `akasha template explain %s` wins. If the wrong one won,\n", f.Provider)
	fmt.Fprintf(&b, "        delete the stale copy, or vault it separately: akasha put %s:<name>\n", f.Provider)
	return b.String()
}
