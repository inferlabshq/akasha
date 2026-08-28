package sandbox

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests EXECUTE the sandbox. Everything else in this package checks what
// we generate; only these check what the kernel does with it — which is the
// distinction the whole self-test mechanism exists for.
//
// They are named *Enforce* so CI can select them, and they respect
// AKASHA_SANDBOX_REQUIRE: on a developer machine without a backend they skip,
// but in CI that variable turns a skip into a failure. A sandbox test that
// quietly skips is exactly how an unenforced sandbox ships.

func requireSandbox(t *testing.T) {
	t.Helper()
	// Root cannot prove any of this. bwrap must CREATE each mount point, and
	// uid 0 can do that anywhere — so a deny set an ordinary user cannot mount
	// launches perfectly here. `akasha run` was broken for every non-root Linux
	// user through four separate causes, and three rounds of verification missed
	// all of them by running as root while this suite stayed green.
	//
	// Skipping under AKASHA_SANDBOX_REQUIRE would be the same mistake the flag
	// exists to prevent, so this is fatal rather than a skip.
	if os.Geteuid() == 0 && os.Getenv("AKASHA_SANDBOX_REQUIRE") == "1" {
		t.Fatal("running as root: these tests cannot detect the sandbox's real failure mode, " +
			"because root can create mount points an ordinary user cannot. Run them as a normal user.")
	}
	if err := Available(); err != nil {
		if os.Getenv("AKASHA_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("AKASHA_SANDBOX_REQUIRE=1 but no working sandbox: %v", err)
		}
		t.Skipf("no sandbox backend on this host: %v", err)
	}
}

// sh runs a command inside the sandbox and returns its combined output.
func sh(t *testing.T, spec Spec, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	if err := Wrap(spec, cmd); err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// specFor builds a spec denying dir, allowing back allowDir.
func specFor(t *testing.T, deny string, allow ...string) Spec {
	t.Helper()
	// DenyPeerProcesses is not optional beside a deny set — Validate refuses
	// the pair, because /proc/<pid>/root walks past every mount without it.
	s := Spec{
		Deny:              []Rule{{Path: deny, Tree: true, Mode: DenyAll, Why: "test secret"}},
		DenyPeerProcesses: true,
	}
	s.AllowWrite = append(s.AllowWrite, allow...)
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return s
}

// TestEnforceDeniesSecret is the core claim: a file the spec denies must not be
// readable from inside.
//
// The assertion is "no secret bytes", NOT a particular errno. bubblewrap serves
// a denied file as EMPTY (it is a bind-mount of /dev/null) while seatbelt
// returns EPERM; both are enforcement, and asserting an errno would make the
// test platform-specific for no security gain.
func TestEnforceDeniesSecret(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	secret := filepath.Join(dir, "vault.db")
	const canary = "CANARY-429210001"
	if err := os.WriteFile(secret, []byte(canary), 0600); err != nil {
		t.Fatal(err)
	}

	// Sanity: readable WITHOUT the sandbox. Without this the test could pass
	// because the file was never readable in the first place.
	if b, err := os.ReadFile(secret); err != nil || !strings.Contains(string(b), canary) {
		t.Fatalf("setup: the canary must be readable outside the sandbox (%v)", err)
	}

	out, _ := sh(t, specFor(t, dir), "cat "+secret+" 2>&1 || true")
	if strings.Contains(out, canary) {
		t.Fatalf("SANDBOX NOT ENFORCING: read the secret from inside:\n%s", out)
	}
}

// The deny is a TREE, so a file created after launch — a rotated audit segment,
// a WAL sidecar — is covered too. This is the property the deny-default island
// exists to provide, and enumeration would not give it.
func TestEnforceDeniesTreeMembersCreatedLater(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	spec := specFor(t, dir)

	const canary = "CANARY-LATER"
	later := filepath.Join(dir, "audit.log.1")
	if err := os.WriteFile(later, []byte(canary), 0600); err != nil {
		t.Fatal(err)
	}
	out, _ := sh(t, spec, "cat "+later+" 2>&1 || true")
	if strings.Contains(out, canary) {
		t.Fatalf("SANDBOX NOT ENFORCING: a file added to a denied tree was readable:\n%s", out)
	}
}

// TestEnforceAllowsSocket is the opposite failure, and just as important: a
// profile that denied the daemon socket would look perfect and break every
// credential operation at runtime — the surest way to get the sandbox disabled.
//
// It goes through SelfTest rather than poking a shell, because SelfTest's
// dial-from-inside check is the exact code `akasha run` relies on.
func TestEnforceAllowsSocket(t *testing.T) {
	requireSandbox(t)
	akashaBin := buildProbeBinary(t)

	// Short path: unix sockets cap near 104 bytes and t.TempDir() under the
	// default TMPDIR can exceed it.
	sockDir, err := os.MkdirTemp("/tmp", "aksk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "a.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	deny := t.TempDir()
	if err := os.WriteFile(filepath.Join(deny, "vault.db"), []byte("CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := specFor(t, deny).AllowSocketPath(sock)
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}

	// Passing means: the secret was blocked AND the socket was still reachable
	// from inside. Both halves matter.
	if err := SelfTest(spec, akashaBin); err != nil {
		t.Fatalf("SelfTest failed on a profile that denies a secret but keeps the socket open: %v", err)
	}
}

// TestEnforceAllowsOrdinaryWork guards the design decision: allow-by-default.
// A jail the agent cannot work in is a jail that gets --no-sandbox'd, so the
// machine must remain usable.
func TestEnforceAllowsOrdinaryWork(t *testing.T) {
	requireSandbox(t)

	work := t.TempDir()
	spec := specFor(t, t.TempDir(), work)

	out, err := sh(t, spec, "echo hello && mkdir -p "+work+"/sub && echo ok > "+work+"/sub/f && cat "+work+"/sub/f")
	if err != nil {
		t.Fatalf("ordinary work failed inside the sandbox (%v):\n%s", err, out)
	}
	for _, want := range []string{"hello", "ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestEnforceSelfTestCatchesUnenforcedProfile is the meta-test: it proves the
// self-test would actually notice.
//
// An EMPTY spec enforces nothing. Running the probe against a real secret under
// that spec must report a leak — if it does not, SelfTest is decorative and
// every "sandbox verified" claim built on it is worthless.
func TestEnforceSelfTestCatchesUnenforcedProfile(t *testing.T) {
	// The failure being modelled is: the profile was generated and accepted, but
	// the kernel is not enforcing it — so a path we believe is denied is in fact
	// readable. That is reproduced here by running the probe child WITHOUT any
	// sandbox at all, which is precisely what "not enforcing" looks like from
	// the child's point of view.
	//
	// An earlier version of this test modelled it as an allow-back covering its
	// own deny. That was wrong: an allow-back is a hole the spec opened ON
	// PURPOSE (~/.ssh is denied as a tree while config and known_hosts stay
	// readable), and SelfTest now skips those deliberately. Modelling the bug
	// that way made the test pass for a reason unrelated to enforcement.
	dir := t.TempDir()
	secret := filepath.Join(dir, "vault.db")
	if err := os.WriteFile(secret, []byte("CANARY"), 0600); err != nil {
		t.Fatal(err)
	}

	res := runProbeUnsandboxed(t, probe{DenyPaths: []string{secret}})
	if len(res.Leaks) != 1 || res.Leaks[0] != secret {
		t.Fatalf("the probe did not report a readable secret as a leak (leaks=%v) — "+
			"SelfTest would not notice an unenforced sandbox", res.Leaks)
	}
}

// A file that is genuinely unreadable must NOT be reported, or every launch
// would be refused for the wrong reason.
func TestEnforceSelfTestChildIgnoresUnreadable(t *testing.T) {
	res := runProbeUnsandboxed(t, probe{DenyPaths: []string{filepath.Join(t.TempDir(), "does-not-exist")}})
	if len(res.Leaks) != 0 {
		t.Fatalf("an unreadable path was reported as a leak: %v", res.Leaks)
	}
}

// runProbeUnsandboxed drives RunSelfTestChild directly, with no sandbox.
func runProbeUnsandboxed(t *testing.T, p probe) probeResult {
	t.Helper()
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.json")
	plan, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inPath, plan, 0600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	outPath := filepath.Join(dir, "out.json")
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunSelfTestChild(in, out, nil); err != nil {
		t.Fatalf("RunSelfTestChild: %v", err)
	}
	out.Close()

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var res probeResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("probe output: %v (%s)", err, raw)
	}
	return res
}

// TestEnforceSelfTestPassesRealProfile: the same probe must PASS when the
// profile really enforces, or `akasha run` would refuse every launch.
func TestEnforceSelfTestPassesRealProfile(t *testing.T) {
	requireSandbox(t)

	akashaBin := buildProbeBinary(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vault.db"), []byte("CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SelfTest(specFor(t, dir), akashaBin); err != nil {
		t.Fatalf("SelfTest rejected a genuinely enforcing profile: %v", err)
	}
}

// buildProbeBinary builds the real akasha binary, whose hidden
// `sandbox-selftest` command is the child half of the self-test.
//
// Building the actual binary rather than a synthetic stand-in also exercises the
// real wiring — including the keychain probe target, which a stand-in would not
// have. A synthetic program also cannot resolve the module from a temp dir.
func buildProbeBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "akasha")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/akasha")
	cmd.Dir = "../.." // the daemon module root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build akasha for the self-test: %v\n%s", err, out)
	}
	return bin
}
