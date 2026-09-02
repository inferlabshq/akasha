package sandbox

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The sandbox must mask the files credentials were actually discovered from,
// not only the well-known stores.
//
// `akasha run` promises that "your plaintext credential files are unreachable"
// and masked a hand-written list — the aws, ssh, gcloud, gh, gnupg and docker
// directories plus netrc, git-credentials and pgpass. akasha's own templates
// declare sixteen places a credential can live, and fourteen were not on it.
// Measured: an AWS key seeded into ~/.zshrc and ~/.env was flagged by
// `akasha discover` as a credential, and read out of both from inside the
// sandbox with sha256 matching in and out.
//
// Masking every declared location would break the run: those globs cover
// ~/.env and ~/projects/.env*, and the shell files that set up PATH. So the
// extra masks come from PROVENANCE — the files this vault's credentials were
// actually found in — which is both narrower and always current.
func TestCredentialSourcesAreMasked(t *testing.T) {
	base := Surface(t.TempDir(), t.TempDir(), nil, nil)
	before := len(base.Deny)

	home := "/Users/someone"
	if runtime.GOOS == "linux" {
		home = "/home/someone"
	}
	shellRC := filepath.Join(home, ".zshrc")
	projectEnv := filepath.Join(home, "projects", "app", ".env")

	spec := base.DenyingCredentialSources([]string{shellRC, projectEnv})
	if len(spec.Deny) != before+2 {
		t.Fatalf("expected 2 extra deny rules, got %d", len(spec.Deny)-before)
	}

	masked := map[string]Rule{}
	for _, r := range spec.Deny {
		masked[r.Path] = r
	}
	for _, want := range []string{shellRC, projectEnv} {
		r, ok := masked[want]
		if !ok {
			t.Errorf("%s was discovered from but is not masked", want)
			continue
		}
		// A FILE, never a tree: these are ordinary paths a user chose, and one
		// of them being a directory would otherwise take a whole project with
		// it.
		if r.Tree {
			t.Errorf("%s is masked as a tree; a project directory would go with it", want)
		}
		if r.Mode != DenyAll {
			t.Errorf("%s is not fully denied", want)
		}
		if r.Why == "" {
			t.Errorf("%s is masked with no stated reason", want)
		}
	}
}

// Anything that is not an absolute path is dropped rather than guessed at:
// these become mount arguments, and a relative or empty entry there is a mask
// on the wrong thing.
func TestCredentialSourcesIgnoreUnusablePaths(t *testing.T) {
	base := Surface(t.TempDir(), t.TempDir(), nil, nil)
	before := len(base.Deny)

	spec := base.DenyingCredentialSources([]string{"", "relative/path", "~/unexpanded"})
	if len(spec.Deny) != before {
		t.Fatalf("unusable source paths became mount rules: %d added", len(spec.Deny)-before)
	}
}

// The doctor must not go back to claiming more than it does. It now says the
// masks follow discovery, and that masking is only as complete as discovery.
func TestDoctorStatesTheProvenanceLimit(t *testing.T) {
	// A synthetic plan rather than one built for this host: Describe() renders
	// the coverage table only where the mount-based backend applies, so asking
	// the platform would skip on macOS — and a skipped test proves nothing
	// about the wording it is here to pin.
	plan := Plan{Dispositions: []Disposition{{
		Path:      "/example/vault",
		Target:    "/example/vault",
		Mechanism: MechTmpfs,
		Why:       "example",
	}}}
	desc := plan.Describe()
	if desc == "" {
		t.Fatal("a plan with a disposition rendered no table")
	}
	for _, want := range []string{"as complete as discovery", "provenance"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the coverage table should state %q:\n%s", want, desc)
		}
	}
	// And it must not go back to the older, wider claim.
	if strings.Contains(desc, "out of scope by choice") {
		t.Error("the table still carries the pre-provenance wording")
	}
}
