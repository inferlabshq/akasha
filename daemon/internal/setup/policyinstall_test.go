package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/policy"
)

// A machine that has never run `akasha policy init` must still get the default
// posture. Before this, setup never mentioned policy at all and the engine
// treats a missing file as allow-all — so the shipped rules were opt-in, and the
// ordinary path (run setup, never read the policy docs) got none of them.
//
// The assertion is on BEHAVIOUR, not on the bytes: what matters is that the
// installed file actually denies the thing it is installed to deny.
func TestSetupInstallsThePolicyOnAMachineWithNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")

	installPolicy(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("setup did not write a policy: %v", err)
	}
	p, err := policy.ParseLenient(data)
	if err != nil {
		t.Fatalf("the policy setup installed does not parse: %v", err)
	}
	if !p.DeniesAgentSessionOnBrokerable() {
		t.Error("the installed default lets an agent hold a session credential for a " +
			"provider that has a per-operation route — which is the case it exists to cover")
	}
}

// The operator's file is theirs. Setup runs more than once, and it may run
// against a policy carrying rules this build has never heard of — so the one
// thing it must never do is rewrite the file it found.
//
// Both branches are checked byte-for-byte, including the branch that PRINTS a
// warning, because "we noticed something is missing" is exactly the moment a
// helpful implementation reaches for the file.
func TestSetupNeverRewritesAnExistingPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			// Already carries the posture, expressed differently from the
			// starter's spelling: a blanket deny rather than one keyed on
			// brokerable. Evaluation says this machine is covered; a structural
			// check looking for the shipped rule would have said it was not and
			// nagged the operator forever.
			name: "already covered, different spelling",
			body: "version: 1\ndefault: allow\nrules:\n  - {action: assume, caller: agent, effect: deny}\n",
		},
		{
			// The case on real machines: a policy written before the rule
			// existed. Setup must report it and leave it alone.
			name: "predates the rule",
			body: "version: 1\ndefault: allow\nrules:\n  - {action: retrieve, effect: deny}\n",
		},
		{
			// A file that does not parse denies everything, so setup must not
			// "fix" it by replacing it — that would silently turn a locked-down
			// machine permissive.
			name: "does not parse",
			body: "version: 1\nrules: [[[\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}

			installPolicy(path)

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("setup removed the operator's policy: %v", err)
			}
			if string(got) != tc.body {
				t.Errorf("setup rewrote a policy it did not create.\n got: %q\nwant: %q", got, tc.body)
			}
		})
	}
}

// The drift notice has to be keyed on the posture rather than on a spelling,
// which is the reason DeniesAgentSessionOnBrokerable evaluates instead of
// pattern-matching. This pins that distinction: an equivalent policy is covered,
// an older one is not.
func TestDriftCheckAsksTheQuestionByEvaluation(t *testing.T) {
	covered, err := policy.ParseLenient([]byte(
		"version: 1\ndefault: allow\nrules:\n  - {action: assume, caller: agent, effect: deny}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !covered.DeniesAgentSessionOnBrokerable() {
		t.Error("a broader deny already expresses the posture and must count as covered")
	}

	stale, err := policy.ParseLenient([]byte(
		"version: 1\ndefault: allow\nrules:\n  - {action: retrieve, effect: deny}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if stale.DeniesAgentSessionOnBrokerable() {
		t.Error("a policy with no assume rule must not be reported as covered")
	}
}
