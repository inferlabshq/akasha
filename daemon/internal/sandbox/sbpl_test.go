package sandbox

import (
	"strings"
	"testing"
)

// The SBPL profile is a GENERATED PROGRAM built from paths, and $HOME is
// user-influenced (macOS permits quotes and backslashes in directory names). A
// quoting bug here is a silent full bypass, so this is the most heavily tested
// corner of the package — and it runs on the Linux CI runner too, via
// DescribeFor, which is the whole reason this package uses a runtime.GOOS switch
// instead of build tags.

func darwinProfile(t *testing.T, s Spec) string {
	t.Helper()
	out, err := DescribeFor("darwin", s)
	if err != nil {
		t.Fatalf("DescribeFor(darwin): %v", err)
	}
	return out
}

func TestSBPLQuotesMetacharacters(t *testing.T) {
	// None of these may terminate the string or add a form.
	for _, p := range []string{
		`/Users/me/dir with spaces/.akasha`,
		`/Users/me/paren(dir)/.akasha`,
		`/Users/me/semi;colon/.akasha`,
		`/Users/me/hash#mark/.akasha`,
		`/Users/me/star*glob/.akasha`,
		`/Users/me/bracket[x]/.akasha`,
	} {
		got, err := sbplString(p)
		if err != nil {
			t.Fatalf("sbplString(%q): %v", p, err)
		}
		if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
			t.Errorf("sbplString(%q) = %s, want a quoted literal", p, got)
		}
		if strings.Count(got, `"`) != 2 {
			t.Errorf("sbplString(%q) = %s: unescaped quote", p, got)
		}
	}
}

// The one that matters: a $HOME crafted to close the string and inject forms.
func TestSBPLInjectionAttempt(t *testing.T) {
	hostile := `/Users/me") (allow default) (deny nothing "x/.akasha`
	profile := darwinProfile(t, Spec{
		Deny: []Rule{{Path: hostile, Tree: true, Mode: DenyAll}},
		// Required beside any deny set, on both platforms: the same Spec can be
		// rendered for Linux (DescribeFor takes the target GOOS), where without
		// a private PID namespace /proc/<pid>/root walks past every mount.
		DenyPeerProcesses: true,
	})

	// Judge the STRUCTURE, not the raw text: the hostile text is present, but
	// it must be inert inside a string literal. Counting raw occurrences would
	// report an injection here even though the escaping worked — and, worse,
	// could not tell a working escape from a broken one.
	structure, unterminated := stripStrings(profile)
	if unterminated {
		t.Fatalf("hostile path left an unterminated literal:\n%s", profile)
	}
	if n := strings.Count(structure, "(allow default)"); n != 1 {
		t.Fatalf("injection succeeded: %d (allow default) forms in the structure\n%s", n, profile)
	}
	if strings.Contains(structure, "deny nothing") {
		t.Fatalf("injected form escaped the literal:\n%s", profile)
	}
	if err := assertWellFormed(profile); err != nil {
		t.Fatalf("hostile path produced a malformed profile: %v\n%s", err, profile)
	}
	// And the hostile text IS still there, quoted — we neutralise, not censor.
	if !strings.Contains(profile, `\"`) {
		t.Fatalf("expected the embedded quote to be escaped:\n%s", profile)
	}
}

// Control bytes are rejected, not escaped — their TinyScheme lexing is not worth
// trusting, and they never occur in a path derived from $HOME plus a fixed name.
func TestSBPLRejectsControlBytes(t *testing.T) {
	for _, p := range []string{"/Users/me/\n.akasha", "/Users/me/\x00.akasha", "/Users/me/\x7f.akasha"} {
		if _, err := sbplString(p); err == nil {
			t.Errorf("sbplString(%q) should have been rejected", p)
		}
	}
}

// The profile must never contain a regex form: with no regex there is no
// metacharacter surface to get wrong, which is why the deny-default islands
// exist instead of filename patterns.
func TestSBPLEmitsNoRegex(t *testing.T) {
	profile := darwinProfile(t, Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
		AllowSocketPath("/tmp/akasha-run-1/akasha.sock"))
	if strings.Contains(profile, "(regex") {
		t.Fatalf("profile contains a regex form:\n%s", profile)
	}
}

// SBPL is last-match-wins, so every allow must come after every deny. This must
// hold regardless of the order a caller listed rules in.
func TestSBPLAllowsFollowDenies(t *testing.T) {
	s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
		AllowSocketPath("/tmp/akasha-run-1/akasha.sock")
	profile := darwinProfile(t, s)

	lastDeny := strings.LastIndex(profile, "\n(deny ")
	firstAllowBack := strings.Index(profile, "\n(allow network-outbound")
	if firstAllowBack == -1 {
		firstAllowBack = strings.Index(profile, "\n(allow file-read*")
	}
	if firstAllowBack == -1 {
		t.Fatalf("no allow-back emitted:\n%s", profile)
	}
	if firstAllowBack < lastDeny {
		t.Fatalf("an allow-back precedes a deny; last-match-wins would drop it:\n%s", profile)
	}
}

// The data directory must be denied as a TREE, so files nobody enumerated —
// rotated audit segments, WAL sidecars, tomorrow's additions — are covered.
func TestSurfaceDeniesDataDirAsTree(t *testing.T) {
	s := Surface("/Users/me/.akasha", "", nil, nil)
	for _, r := range s.Deny {
		if r.Path == "/Users/me/.akasha" {
			if !r.Tree {
				t.Fatal("the akasha data directory must be denied as a subtree")
			}
			return
		}
	}
	t.Fatal("the akasha data directory is not denied at all")
}

// INVARIANT: no template-derived value may reach the generated profile.
//
// The run dir is allowed as ONE subpath rule, never one rule per rendered file.
// The obvious future "optimisation" — enumerate what AssembleOwnership wrote and
// allow each — would route a template-controlled filename into generated code.
// safeName makes that survivable today, which is exactly why the regression
// would go unnoticed.
func TestNoTemplateValueInProfile(t *testing.T) {
	const runDir = "/tmp/akasha-run-abc"
	s := Surface("/Users/me/.akasha", runDir, nil, nil).
		AllowSocketPath(runDir + "/akasha.sock")

	profile := darwinProfile(t, s)
	sentinel := "github.gitconfig" // a filename a provider template chooses
	if strings.Contains(profile, sentinel) {
		t.Fatalf("a template-derived filename reached the generated profile:\n%s", profile)
	}
	if !strings.Contains(profile, runDir) {
		t.Fatalf("the run dir itself must be allowed:\n%s", profile)
	}

	argv, err := DescribeFor("linux", s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(argv, sentinel) {
		t.Fatalf("a template-derived filename reached the bwrap argv:\n%s", argv)
	}
}

func TestValidateRejectsDangerousPaths(t *testing.T) {
	for _, p := range []string{
		"/",                       // would become --tmpfs / on Linux
		"/Users",                  // too shallow
		"relative/path",           // not absolute
		"/Users/me/../etc/passwd", // traversal
		"/Users/me/./x",           // not clean
		"/etc/../etc",             // not clean
		"/nonsense/root/path",     // outside the allowed roots
	} {
		s := Spec{Deny: []Rule{{Path: p, Tree: true}}, DenyPeerProcesses: true}
		if err := s.Validate(); err == nil {
			t.Errorf("Validate accepted dangerous path %q", p)
		}
	}
	// A legitimate one still passes.
	ok := Spec{Deny: []Rule{{Path: "/Users/me/.akasha", Tree: true}}, DenyPeerProcesses: true}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate rejected a legitimate path: %v", err)
	}
}

// bwrap: every deny must precede every allow-back, since mount order is argv
// order and a later bind has to punch through an earlier tmpfs.
func TestBwrapDeniesPrecedeAllows(t *testing.T) {
	s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
		AllowSocketPath("/tmp/akasha-run-1/akasha.sock")
	argv, err := bwrapArgv(s, "/usr/bin/bwrap", []string{"/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	lastDeny, firstAllow := -1, -1
	for i, a := range argv {
		switch a {
		case "--tmpfs":
			lastDeny = i
		case "--ro-bind", "--bind":
			// --bind /dev/null is a deny, not an allow-back.
			if i+1 < len(argv) && argv[i+1] == "/dev/null" {
				lastDeny = i
				continue
			}
			if firstAllow == -1 {
				firstAllow = i
			}
		}
	}
	if firstAllow == -1 {
		t.Fatalf("no allow-back in argv: %v", argv)
	}
	if firstAllow < lastDeny {
		t.Fatalf("an allow-back precedes a deny mount; the tmpfs would bury it:\n%v", argv)
	}
	if argv[1] != "--dev-bind" || argv[2] != "/" || argv[3] != "/" {
		t.Fatalf("argv must start with --dev-bind / / to be allow-by-default: %v", argv[:4])
	}
}
