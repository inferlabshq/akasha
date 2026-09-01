package hardening

import (
	"strings"
	"testing"
)

// A control that quietly did nothing is the failure this project keeps finding,
// so the summary must never read as "hardened" when nothing was applied.
func TestSummaryNeverReadsAsAppliedWhenItIsNot(t *testing.T) {
	if got := (Result{}).Summary(); !strings.Contains(got, "none") {
		t.Errorf("an empty result summarised as %q", got)
	}
	got := Result{Skipped: []string{"disabled by X"}}.Summary()
	if !strings.HasPrefix(got, "NONE") {
		t.Errorf("a fully skipped result summarised as %q, which does not read as a no-op", got)
	}
	got = Result{Applied: []string{"non-dumpable"}, Skipped: []string{"anti-ptrace (needs cgo)"}}.Summary()
	for _, want := range []string{"non-dumpable", "not applied", "anti-ptrace"} {
		if !strings.Contains(got, want) {
			t.Errorf("a partial result lost %q: %q", want, got)
		}
	}
}

// The escape hatch has to be visible in the output, or a machine that silently
// stopped hardening looks identical to one that never did.
func TestDisableIsReported(t *testing.T) {
	t.Setenv(DisableEnv, "1")
	r := Apply()
	if len(r.Applied) != 0 {
		t.Errorf("hardening applied despite %s: %v", DisableEnv, r.Applied)
	}
	if !strings.Contains(r.Summary(), DisableEnv) {
		t.Errorf("the summary does not name why nothing was applied: %q", r.Summary())
	}
}

// On a supported platform something must actually be applied, or the wiring is
// present and inert.
func TestApplyDoesSomething(t *testing.T) {
	if r := Apply(); len(r.Applied) == 0 {
		t.Errorf("nothing was applied on this platform: %s", r.Summary())
	}
}
