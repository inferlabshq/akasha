package sandbox

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// A PLAN is the renderer's account of what it did with every rule it was given.
//
// This exists because of a single line — `continue` — in the deny loop. A rule
// the renderer could not place was silently dropped, and a dropped mask is
// indistinguishable from a satisfied one in every artefact anyone looked at:
// the argv, `--print-profile`, the self-test, and `go test ./...`. That is the
// direct cause of this package's entire bug history. Four rewrites of the
// placement rule shipped with the suite fully green, each one leaking a
// different path, because nothing anywhere said "this rule enforces nothing".
//
// So the fix is not another placement rule. It is that a rule can no longer
// leave the renderer without an answer attached to it. record is the ONLY
// way a deny rule exits the loop, and Assert refuses to launch if the count of
// answers does not match the count of rules — which turns "someone adds a new
// early-exit and forgets to record it" from a silent hole into a failed launch.

// Mechanism is how a rule was enforced, or why it was not.
type Mechanism string

const (
	// MechTmpfs replaces a directory with an empty tmpfs.
	MechTmpfs Mechanism = "tmpfs"
	// MechNullBind replaces a file with /dev/null. It reads as empty rather
	// than refusing, which SelfTest accounts for: its criterion is "no secret
	// bytes", not a specific errno.
	MechNullBind Mechanism = "null-bind"
	// MechIsland means the name does not exist inside at all, because the
	// directory holding it was rebuilt without it. Stronger than a mask: it
	// covers a path created after launch.
	MechIsland Mechanism = "island"
	// MechOtherOS means the rule belongs to the other platform. Not a gap.
	MechOtherOS Mechanism = "other-os"
	// MechUnplaceable means no mount could be put there — and, crucially, that
	// nothing inside the sandbox can create the path either, which is what
	// makes it safe to leave alone. See denyTargetPlaceable.
	MechUnplaceable Mechanism = "unplaceable"
)

// enforcing reports whether this mechanism actually masks something.
func (m Mechanism) enforcing() bool {
	return m == MechTmpfs || m == MechNullBind || m == MechIsland
}

// Disposition is what became of one rule.
type Disposition struct {
	Path      string // as declared in the Spec
	Target    string // where the mount landed; empty when nothing was mounted
	Mechanism Mechanism
	Why       string // the rule's own Why, carried through
	Reason    string // why this mechanism and not another; required when not enforcing
	Residual  string // what this mechanism does NOT cover
	ReadOnly  bool   // a deferred --remount-ro seals it
}

// Plan is the whole account, one entry per rule.
type Plan struct {
	Dispositions []Disposition
}

func (p *Plan) record(d Disposition) { p.Dispositions = append(p.Dispositions, d) }

// Assert checks the plan against the spec it came from.
//
// Two invariants, both about the renderer rather than the host:
//
//   - every deny rule produced exactly one disposition, so no code path can
//     drop a rule without saying so;
//   - a disposition that does not enforce carries a reason, so "unenforced" can
//     never be the quiet default.
//
// Deliberately NOT asserted: that everything is enforced. Some rules genuinely
// should not be — a macOS path on Linux, or a path this user could not create
// even if it tried. Demanding full enforcement would push the next person to
// weaken the rule rather than record the truth, which is how the fail-open
// version of this package got written.
func (p Plan) Assert(spec Spec) error {
	// EVERY rule, including the other platform's — a rule skipped for its OS
	// still has to say so, or "wrong tag" and "silently dropped" look alike.
	want := len(spec.Deny)
	if got := len(p.Dispositions); got != want {
		return fmt.Errorf("sandbox: the render plan has %d dispositions for %d deny rules — "+
			"a rule left the renderer with no account of what happened to it, which is exactly "+
			"the silent drop this type exists to make impossible", got, want)
	}
	for _, d := range p.Dispositions {
		if !d.Mechanism.enforcing() && d.Reason == "" {
			return fmt.Errorf("sandbox: %s is not enforced (%s) and no reason was recorded; "+
				"an unenforced rule must say why", d.Path, d.Mechanism)
		}
		if d.Mechanism.enforcing() && d.Target == "" {
			return fmt.Errorf("sandbox: %s claims to be enforced by %s but names no target",
				d.Path, d.Mechanism)
		}
	}
	return nil
}

// Unenforced returns the rules that mask nothing, for a caller that wants to
// surface them.
func (p Plan) Unenforced() []Disposition {
	var out []Disposition
	for _, d := range p.Dispositions {
		if !d.Mechanism.enforcing() {
			out = append(out, d)
		}
	}
	return out
}

// Describe renders the plan as a human-readable table.
//
// Sorted by path so two profiles can be diffed. The unenforced rules are listed
// SEPARATELY and last rather than mixed in, because the whole point is that a
// reader should not have to scan a column to find them.
func (p Plan) Describe() string {
	if len(p.Dispositions) == 0 {
		return ""
	}
	sorted := append([]Disposition(nil), p.Dispositions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	var b strings.Builder
	w := func(format string, a ...interface{}) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# What this profile does with each rule.")
	w("#")
	w("# Every rule appears here. A rule cannot be dropped without a line, which")
	w("# is enforced rather than intended — see Plan.Assert.")
	w("#")
	for _, d := range sorted {
		if !d.Mechanism.enforcing() {
			continue
		}
		seal := ""
		if d.ReadOnly {
			seal = " +remount-ro"
		}
		w("#   %-11s %s%s", d.Mechanism, d.Path, seal)
		if d.Target != "" && d.Target != d.Path {
			w("#               -> %s", d.Target)
		}
		if d.Residual != "" {
			w("#               residual: %s", d.Residual)
		}
	}

	un := []Disposition{}
	for _, d := range sorted {
		if !d.Mechanism.enforcing() {
			un = append(un, d)
		}
	}
	if len(un) > 0 {
		w("#")
		w("# NOT MASKED (%d). Each of these enforces nothing; the reason is why", len(un))
		w("# that is safe, and is the first thing to check if a secret leaks.")
		for _, d := range un {
			w("#   %-11s %s", d.Mechanism, d.Path)
			w("#               %s", d.Reason)
		}
	}
	return b.String()
}

// planFor returns what the renderer would do with spec, without needing a
// command to wrap.
//
// The bin and command are placeholders: neither influences a single
// disposition. Going through compile rather than reimplementing the walk is the
// point — a second implementation could disagree with the first, and then the
// verification and the thing it verifies would be two different programs.
func planFor(spec Spec) (Plan, error) {
	if runtime.GOOS != "linux" {
		return Plan{}, nil // seatbelt has no mounts to account for
	}
	_, plan, err := compile(spec, "/usr/bin/bwrap", []string{"<probe>"})
	return plan, err
}
