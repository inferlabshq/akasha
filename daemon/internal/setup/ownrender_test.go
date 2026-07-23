package setup

import (
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// The renderer is the security boundary: whatever the template says, the only
// command emitted is the akasha binary, and structural params can't break out.

func TestRenderOwnAlwaysEmitsAkashaCommand(t *testing.T) {
	d := template.OwnDirective{
		Mechanism: template.MechCredentialProcess,
		Env:       "AWS_CONFIG_FILE", File: "aws.config", Section: "profile {instance}",
	}
	r := renderOwn(d, "aws", "/usr/bin/akasha", "/agentdir", []string{"default"})
	if r.envName != "AWS_CONFIG_FILE" || r.envValue != "/agentdir/aws.config" {
		t.Fatalf("env wiring wrong: %+v", r)
	}
	if !strings.Contains(string(r.content), "credential_process = /usr/bin/akasha helper aws --instance default") {
		t.Fatalf("command must be the akasha binary:\n%s", r.content)
	}
}

func TestRenderOwnFiltersUnsafeInstances(t *testing.T) {
	d := template.OwnDirective{
		Mechanism: template.MechCredentialProcess,
		Env:       "E", File: "f", Section: "profile {instance}",
	}
	// Even if a malicious instance name reaches the renderer, it cannot inject
	// config structure — it is dropped.
	r := renderOwn(d, "aws", "akasha", "/d", []string{"ok", "ev]il\ncredential_process = sh", "a b"})
	s := string(r.content)
	if !strings.Contains(s, "profile ok") {
		t.Fatalf("safe instance dropped:\n%s", s)
	}
	if strings.Contains(s, "ev]il") || strings.Contains(s, "a b") || strings.Contains(s, "= sh") {
		t.Fatalf("unsafe instance leaked into config:\n%s", s)
	}
}

func TestRenderOwnGitHelper(t *testing.T) {
	d := template.OwnDirective{
		Mechanism: template.MechGitCredentialHelper,
		Env:       "GIT_CONFIG_GLOBAL", File: "g", Host: "github.com", Inherit: true,
	}
	s := string(renderOwn(d, "github", "akasha", "/d", []string{"default"}).content)
	for _, want := range []string{
		"[include]", "path = ~/.gitconfig",
		`[credential "https://github.com"]`,
		"helper =\n", // the reset
		"helper = !akasha helper github --instance default",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("git helper output missing %q:\n%s", want, s)
		}
	}
}

func TestRenderOwnDecoyWritesEmpty(t *testing.T) {
	d := template.OwnDirective{Mechanism: template.MechDecoy, Env: "AWS_SHARED_CREDENTIALS_FILE", File: "credentials.empty"}
	r := renderOwn(d, "aws", "akasha", "/d", nil)
	if !r.write || len(r.content) != 0 {
		t.Fatalf("decoy should write an empty file: write=%v len=%d", r.write, len(r.content))
	}
}
