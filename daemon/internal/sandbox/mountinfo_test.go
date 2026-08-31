package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mountinfo escapes space, tab, newline and backslash as octal. A mount point
// this failed to decode would be reported missing, so the parser errs toward a
// false alarm rather than a false pass — but a directory with a space in it is
// ordinary enough that a false alarm would be a real bug.
func TestUnescapeMountPoint(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/home/dev/.aws", "/home/dev/.aws"},
		{`/mnt/My\040Drive`, "/mnt/My Drive"},
		{`/tmp/a\011b`, "/tmp/a\tb"},
		{`/tmp/back\134slash`, `/tmp/back\slash`},
		{`/tmp/trailing\04`, `/tmp/trailing\04`}, // too short to be an escape; left alone
		{`/tmp/not\999octal`, `/tmp/not\999octal`},
	} {
		if got := unescapeMountPoint(c.in); got != c.want {
			t.Errorf("unescapeMountPoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The check that closes the gap every earlier probe had.
//
// A read probe calls an empty result enforcement, which is true — but it means
// "masked" and "was never there" produce the same pass. Every one of this
// package's four leaks was a mask that had been skipped for a path holding
// nothing yet, so the read probe found nothing and the self-test went green.
// A mount is either in the table or it is not.
func TestChildReportsAMaskThatIsNotMounted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mountinfo is Linux-only")
	}
	res := runChildProbe(t, probe{ExpectMounts: []string{"/definitely/not/mounted"}})
	if len(res.MissingMounts) != 1 || res.MissingMounts[0] != "/definitely/not/mounted" {
		t.Fatalf("a mask that is not mounted was not reported: %+v", res)
	}

	// …and a mount that IS there must not be reported, or the check fails every
	// launch and gets removed.
	res = runChildProbe(t, probe{ExpectMounts: []string{"/proc"}})
	if len(res.MissingMounts) != 0 {
		t.Errorf("/proc is mounted but was reported missing: %+v", res)
	}
}

// runChildProbe drives RunSelfTestChild in-process over pipes.
func runChildProbe(t *testing.T, p probe) probeResult {
	t.Helper()
	dir := t.TempDir()
	inPath, outPath := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunSelfTestChild(in, out, nil); err != nil {
		t.Fatal(err)
	}
	out.Close()

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var res probeResult
	if err := json.Unmarshal(bytes.TrimSpace(raw), &res); err != nil {
		t.Fatalf("unreadable child output %q: %v", raw, err)
	}
	return res
}

// Every mask the renderer claims must be handed to the child to verify. A
// disposition that never reaches ExpectMounts is a claim nobody checks.
func TestEveryEnforcedMaskIsHandedToTheChild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ExpectMounts is Linux-only")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	spec := Surface(home+"/.akasha", t.TempDir(), nil, nil)
	plan, err := planFor(spec)
	if err != nil {
		t.Fatal(err)
	}
	p := planProbe(spec, plan)

	want := map[string]bool{}
	for _, d := range plan.Dispositions {
		if d.Mechanism.enforcing() && d.Target != "" {
			want[d.Target] = true
		}
	}
	got := map[string]bool{}
	for _, m := range p.ExpectMounts {
		got[m] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("%s is claimed as masked but the child is never asked to confirm it", w)
		}
	}
	if len(want) == 0 {
		t.Fatal("no enforced masks at all — this test would pass vacuously")
	}
}

// A mistyped --allow-read must name the flag and the path, not surface as
// bwrap's "Can't find source path".
func TestMistypedAllowReadIsRefusedClearly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this is the bwrap launch path")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(bwrapEnv, "/usr/bin/bwrap")
	spec := Surface(home+"/.akasha", t.TempDir(), []string{home + "/projct"}, nil)

	cmd := exec.Command("/bin/true")
	err = Wrap(spec, cmd)
	if err == nil {
		t.Fatal("a nonexistent --allow-read path was accepted")
	}
	for _, want := range []string{"--allow-read", "projct", "spelling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}
