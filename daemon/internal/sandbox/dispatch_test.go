package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestApparmorKnobIsReadNotGuessed(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		content string // "" = file absent (a kernel without the knob)
		want    bool
	}{{"1\n", true}, {"0\n", false}, {"", false}} {
		knob := filepath.Join(dir, "knob")
		os.Remove(knob)
		if c.content != "" {
			if err := os.WriteFile(knob, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		old := apparmorUserNSKnob
		apparmorUserNSKnob = knob
		got := apparmorRestrictsUserNS()
		apparmorUserNSKnob = old
		if got != c.want {
			t.Errorf("knob %q: restricted = %v, want %v", c.content, got, c.want)
		}
	}
}

// A path that cannot resolve, so EvalSymlinks falls back and the test does not
// depend on where (or whether) the CI host has bwrap.
const fakeBwrap = "/nonexistent/bin/bwrap"

func appArmorErr() error {
	return fmt.Errorf("wrapped: %w", &userNSError{
		bin: fakeBwrap, out: "bwrap: setting up uid map: Permission denied", apparmor: true,
	})
}

func TestExplainOffersTheAppArmorProfileBeforeTheGlobalSwitches(t *testing.T) {
	msg := Explain(appArmorErr())
	profile := strings.Index(msg, "apparmor_parser -r /etc/apparmor.d/akasha-bwrap")
	sysctl := strings.Index(msg, "sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
	setuid := strings.Index(msg, "chmod u+s "+fakeBwrap)
	if profile < 0 || sysctl < 0 || setuid < 0 {
		t.Fatalf("missing a fix (profile %d, sysctl %d, setuid %d):\n%s", profile, sysctl, setuid, msg)
	}
	if !(profile < sysctl && profile < setuid) {
		t.Errorf("the per-binary profile must come before both global switches:\n%s", msg)
	}
	for _, want := range []string{
		"profile akasha-bwrap " + fakeBwrap + " flags=(unconfined) { userns, }",
		"setting up uid map: Permission denied", // the probe's own words survive
		"--no-sandbox",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q:\n%s", want, msg)
		}
	}
}

func TestExplainKeepsTheGenericAdviceOffUbuntu(t *testing.T) {
	msg := Explain(&userNSError{bin: fakeBwrap, out: "denied", apparmor: false})
	if strings.Contains(msg, "akasha-bwrap") {
		t.Errorf("a host without the AppArmor restriction was offered the profile:\n%s", msg)
	}
	if !strings.Contains(msg, "kernel.unprivileged_userns_clone=1") {
		t.Errorf("the per-distro switches are gone:\n%s", msg)
	}
}

// The guidance is a command people paste. Run its printf through a real shell
// and hand the result to apparmor_parser in parse-only mode (-Q: nothing loads),
// so a quoting slip in the message fails here, not on a user's machine.
func TestAppArmorGuidanceProducesAProfileTheParserAccepts(t *testing.T) {
	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		t.Skip("apparmor_parser not installed")
	}
	if _, err := os.Stat("/etc/apparmor.d/tunables/global"); err != nil {
		t.Skip("no AppArmor tunables on this host")
	}
	msg := Explain(appArmorErr())
	start := strings.Index(msg, "printf ")
	end := strings.Index(msg, "| sudo tee")
	if start < 0 || end < start {
		t.Fatalf("no printf ... | sudo tee pipeline in:\n%s", msg)
	}
	out, err := exec.Command("sh", "-c", msg[start:end]).Output()
	if err != nil {
		t.Fatalf("the printf line does not run: %v", err)
	}
	f := filepath.Join(t.TempDir(), "akasha-bwrap")
	if err := os.WriteFile(f, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(parser, "-Q", "-K", "-T", f).CombinedOutput(); err != nil {
		t.Fatalf("apparmor_parser rejects the profile the guidance writes: %v\n%s\nprofile:\n%s", err, b, out)
	}
}
