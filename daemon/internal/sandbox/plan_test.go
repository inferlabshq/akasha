package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The invariant the whole type exists for: a rule cannot leave the renderer
// without an account of what happened to it.
//
// Four rewrites of the placement rule shipped with `go test ./...` fully green,
// each leaking a different path, because a dropped mask and a satisfied one look
// identical in the argv. This is the check that tells them apart.
func TestEveryDenyRuleGetsADisposition(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)

	_, plan, err := compile(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Dispositions) != len(spec.Deny) {
		t.Fatalf("%d dispositions for %d rules", len(plan.Dispositions), len(spec.Deny))
	}
	seen := map[string]bool{}
	for _, d := range plan.Dispositions {
		seen[d.Path] = true
		if d.Mechanism == "" {
			t.Errorf("%s has no mechanism", d.Path)
		}
	}
	for _, r := range spec.Deny {
		if !seen[r.Path] {
			t.Errorf("%s is in the deny set but absent from the plan — this is the silent drop", r.Path)
		}
	}
}

// Assert must actually catch a missing rule, or the invariant above is a
// comment rather than a guarantee.
func TestAssertCatchesADroppedRule(t *testing.T) {
	spec := Spec{
		DenyPeerProcesses: true,
		Deny: []Rule{
			{Path: "/home/dev/.aws", Tree: true, Mode: DenyAll},
			{Path: "/home/dev/.netrc", Mode: DenyAll},
		},
	}
	full := Plan{Dispositions: []Disposition{
		{Path: "/home/dev/.aws", Target: "/home/dev/.aws", Mechanism: MechTmpfs},
		{Path: "/home/dev/.netrc", Target: "/home/dev/.netrc", Mechanism: MechNullBind},
	}}
	if err := full.Assert(spec); err != nil {
		t.Fatalf("a complete plan was rejected: %v", err)
	}

	dropped := Plan{Dispositions: full.Dispositions[:1]}
	if err := dropped.Assert(spec); err == nil {
		t.Error("Assert accepted a plan that had lost a rule")
	}

	// An unenforced rule with no reason is the other half: "unenforced" must
	// never be reachable as a quiet default.
	silent := Plan{Dispositions: []Disposition{
		full.Dispositions[0],
		{Path: "/home/dev/.netrc", Mechanism: MechUnplaceable},
	}}
	if err := silent.Assert(spec); err == nil {
		t.Error("Assert accepted an unenforced rule that recorded no reason")
	} else if !strings.Contains(err.Error(), "why") {
		t.Errorf("the refusal should ask for a reason, got: %v", err)
	}

	// And a rule claiming enforcement without a target is a plan that lies.
	lying := Plan{Dispositions: []Disposition{
		full.Dispositions[0],
		{Path: "/home/dev/.netrc", Mechanism: MechNullBind},
	}}
	if err := lying.Assert(spec); err == nil {
		t.Error("Assert accepted a rule that claims to be enforced but names no target")
	}
}

// A rule that masks nothing must be visible in the profile, and visible as
// such — not mixed in with the ones that do.
func TestUnenforcedRulesAreNamedInTheProfile(t *testing.T) {
	p := Plan{Dispositions: []Disposition{
		{Path: "/home/dev/.aws", Target: "/home/dev/.aws", Mechanism: MechTmpfs, ReadOnly: true},
		{Path: "/Library/Keychains", Mechanism: MechOtherOS, Reason: "a darwin path"},
	}}
	out := p.Describe()
	if !strings.Contains(out, "NOT MASKED (1)") {
		t.Errorf("the profile does not count the unmasked rules:\n%s", out)
	}
	if !strings.Contains(out, "/Library/Keychains") || !strings.Contains(out, "a darwin path") {
		t.Errorf("the unmasked rule or its reason is missing:\n%s", out)
	}
	if !strings.Contains(out, "+remount-ro") {
		t.Errorf("the read-only seal is not shown:\n%s", out)
	}
}

// DenyWrite means "readable, never writable". On macOS that renders as
// file-write* only. On linux it rendered as a tmpfs, which HIDES the contents
// and — with no seal — left the directory writable: the opposite rule in both
// directions, from the same Spec.
//
// Nothing in Surface() uses DenyWrite yet, so no shipped behaviour was wrong.
// The claim that one Spec means the same thing on both platforms was.
func TestDenyWriteKeepsContentsReadableOnLinux(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "config")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := Spec{
		DenyPeerProcesses: true,
		Deny:              []Rule{{Path: target, Tree: true, Mode: DenyWrite, Why: "integrity"}},
	}
	argv, plan, err := compile(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "--tmpfs "+target) {
		t.Errorf("DenyWrite rendered as a tmpfs, which hides the contents it is supposed to keep "+
			"readable:\n%s", joined)
	}
	if !strings.Contains(joined, "--ro-bind "+target+" "+target) {
		t.Errorf("DenyWrite did not render as a read-only bind:\n%s", joined)
	}
	if d := plan.Dispositions[0]; !d.ReadOnly {
		t.Errorf("the disposition does not record the read-only seal: %+v", d)
	}
}

// The plan and the argv are produced by one function so they cannot disagree.
// A caller that renders one without the other is the failure mode this guards.
func TestPlanAndArgvAgreeOnWhatWasMounted(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)

	argv, plan, err := compile(spec, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, d := range plan.Dispositions {
		switch d.Mechanism {
		case MechTmpfs:
			if d.Target != "" && !strings.Contains(joined, "--tmpfs "+d.Target) &&
				!strings.Contains(joined, "--ro-bind "+d.Target) {
				t.Errorf("plan says %s is masked by a tmpfs at %s, but the argv has no such mount",
					d.Path, d.Target)
			}
		case MechNullBind:
			if !strings.Contains(joined, "--bind /dev/null "+d.Target) {
				t.Errorf("plan says %s is masked by /dev/null, but the argv has no such bind", d.Path)
			}
		case MechOtherOS, MechUnplaceable:
			if strings.Contains(joined, " "+d.Path+" ") {
				t.Errorf("plan says %s enforces nothing, but it appears in the argv", d.Path)
			}
		}
	}
}
