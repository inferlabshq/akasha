package provision

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Review renders "here is what was found on your machine" — the listing that
// has to be on screen before anything is written to the vault.
//
// It lives beside the vaulting plumbing, and not in the discover command, for
// the reason that plumbing does: `akasha setup` vaulted every finding with no
// listing and no question, so the consent UI existed only on the command a user
// reaches SECOND. The first-run path is the one that most needs it.
// ReviewContext is what the listing needs in order to say which findings are
// unusual. Empty is valid and simply omits those marks.
type ReviewContext struct {
	// Known is the set of provider:instance labels already vaulted.
	Known map[string]bool
	// Now anchors the freshness marks. Injected so a test is not a race.
	Now time.Time
}

// FreshWindow is how recently a credential file must have been written for the
// listing to point at it.
//
// Wide enough to cover "an agent wrote this during the session you are in", and
// narrow enough that a file you edited yourself this morning does not get
// flagged and teach you to ignore the mark. The mark is an invitation to look,
// not a verdict — it says when the file was written, and lets the person who
// knows what they were doing decide.
const FreshWindow = 30 * time.Minute

func Review(findings []template.Finding) string { return ReviewWith(findings, ReviewContext{}) }

// ReviewWith renders the listing, marking findings that deserve a second look.
//
// Discovery believes the disk, because on a single-uid machine there is nothing
// else to believe. An agent that can write ~/.env can wait for the human's next
// discovery run and have its own value vaulted under their name — and until now
// every finding looked exactly alike in this listing, so a planted one was
// indistinguishable from a real one.
//
// This does not close that. Nothing in a credential scanner can, and a patient
// agent defeats both marks by planting a file for a provider you already use
// and waiting an hour. What it removes is the case where the listing gave the
// reader nothing at all to notice: a provider you have never had before, and a
// file written moments ago, are the two signals a person can actually act on.
func ReviewWith(findings []template.Finding, ctx ReviewContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Found %d credential(s):\n\n", len(findings))
	flagged := 0
	for i, f := range findings {
		marks := reviewMarks(f, ctx)
		if len(marks) > 0 {
			flagged++
		}
		fmt.Fprintf(&b, "  [%d] %s:%s%s\n", i+1, f.Provider, f.Instance, firstMark(marks))
		fmt.Fprintf(&b, "      source: %s%s\n", f.Source, secondMark(marks))
		fmt.Fprintf(&b, "      fields: %s\n", describeFields(f.Fields))
		b.WriteString(describeIncomplete(f))
		b.WriteString(describeShadowed(f))
		b.WriteByte('\n')
	}
	if flagged > 0 {
		b.WriteString(fmt.Sprintf(
			"  ⚠ %d marked above. A credential you have never vaulted before, or a file written\n"+
				"    in the last %d minutes, is worth a second look: anything running as you can\n"+
				"    write a credential file and wait for you to run this.\n\n",
			flagged, int(FreshWindow.Minutes())))
	}
	return b.String()
}

// reviewMarks returns the notes for one finding, in display order.
func reviewMarks(f template.Finding, ctx ReviewContext) []string {
	var marks []string
	// len, not nil. A running daemon with an empty vault answers /label/list
	// with an empty list, which is a perfectly good answer meaning "nothing is
	// vaulted" — and on that first run EVERY finding is new, so marking them
	// all flags the whole listing and teaches the reader to skip the mark
	// before they reach the end of it. With nothing vaulted there is no basis
	// to call anything unusual, which is the same position as having no answer.
	if len(ctx.Known) > 0 && !ctx.Known[f.Provider+":"+f.Instance] {
		// Say which of the two it is. "no ssh credential vaulted before" is
		// false on a machine that already has ssh:id_ed25519 — the INSTANCE is
		// new, not the provider — and a warning that overstates is one people
		// learn to discount, which costs more than the warning earns.
		if knowsProvider(ctx.Known, f.Provider) {
			marks = append(marks, "⚠ NEW — no "+f.Provider+":"+f.Instance+" vaulted before")
		} else {
			marks = append(marks, "⚠ NEW — no "+f.Provider+" credential vaulted before")
		}
	}
	if !ctx.Now.IsZero() && !f.ModTime.IsZero() {
		if age := ctx.Now.Sub(f.ModTime); age >= 0 && age < FreshWindow {
			marks = append(marks, "⚠ written "+humanAge(age)+" ago")
		}
	}
	return marks
}

func firstMark(marks []string) string {
	for _, m := range marks {
		if strings.HasPrefix(m, "⚠ NEW") {
			return "   " + m
		}
	}
	return ""
}

func secondMark(marks []string) string {
	for _, m := range marks {
		if !strings.HasPrefix(m, "⚠ NEW") {
			return "   " + m
		}
	}
	return ""
}

// knowsProvider reports whether any instance of this provider is vaulted.
func knowsProvider(known map[string]bool, provider string) bool {
	for name := range known {
		if strings.HasPrefix(name, provider+":") {
			return true
		}
	}
	return false
}

// humanAge renders a short duration the way a person would say it.
func humanAge(d time.Duration) string {
	switch {
	case d < 5*time.Second:
		return "moments"
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d < 2*time.Minute:
		return "a minute"
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
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
	fmt.Fprintf(&b, "        One credential can hold the name %s:%s. The winner is the first\n", f.Provider, f.Instance)
	fmt.Fprintf(&b, "        COMPLETE one in the order `akasha template explain %s` lists — a\n", f.Provider)
	fmt.Fprintf(&b, "        partial copy does not take the name from a usable one. If the wrong\n")
	fmt.Fprintf(&b, "        one won, delete the stale copy, or vault it separately:\n")
	fmt.Fprintf(&b, "        akasha put %s:<name>\n", f.Provider)
	return b.String()
}

// describeIncomplete flags a credential that cannot satisfy its provider.
//
// Precedence now prefers a usable credential over a partial one, so reaching
// this line means NONE of the copies found under this name were complete. That
// is worth a word on screen, because the alternative is the failure this whole
// path exists to prevent: a green "✓ vaulted", and then a `missing required
// field` from the first command that tries to use it, days later, naming a
// vault the user cannot open and read.
func describeIncomplete(f template.Finding) string {
	if !f.Incomplete {
		return ""
	}
	return fmt.Sprintf("      ! incomplete — %s needs more than this to authenticate; "+
		"vaulting it will not make `%s` work until the rest is added\n",
		f.Provider, "akasha helper "+f.Provider)
}
