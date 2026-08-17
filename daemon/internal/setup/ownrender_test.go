package setup

import (
	"os"
	"path/filepath"
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
	if !strings.Contains(string(r.body), "credential_process = /usr/bin/akasha helper aws --instance default") {
		t.Fatalf("command must be the akasha binary:\n%s", r.body)
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
	s := string(r.body)
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
	r := renderOwn(d, "github", "akasha", "/d", []string{"default"})
	// [include] is the once-per-file preamble; the credential block is the body.
	if !strings.Contains(string(r.preamble), "[include]") || !strings.Contains(string(r.preamble), "path = ~/.gitconfig") {
		t.Fatalf("preamble missing include:\n%s", r.preamble)
	}
	s := string(r.body)
	for _, want := range []string{
		`[credential "https://github.com"]`,
		"helper =\n", // the reset
		"helper = !akasha helper github --instance default",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("git helper body missing %q:\n%s", want, s)
		}
	}
}

// GUARANTEE: setting up an agent never destroys the user's git identity.
// GIT_CONFIG_GLOBAL REPLACES ~/.gitconfig, so exporting it while writing no
// file would give every agent session an empty global config — no user.name,
// no user.email, no signing key. With zero vaulted instances the file must
// still exist and still re-include the user's real gitconfig.
func TestAssembleOwnershipZeroInstancesStillIncludesUserGitconfig(t *testing.T) {
	dir := t.TempDir()
	d := template.OwnDirective{
		Mechanism: template.MechGitCredentialHelper,
		Env:       "GIT_CONFIG_GLOBAL", File: "github.gitconfig", Host: "github.com", Inherit: true,
	}
	env, err := AssembleOwnership(dir, "/usr/bin/akasha", []OwnInput{
		{Provider: "github", Own: []template.OwnDirective{d}, Instances: nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := env["GIT_CONFIG_GLOBAL"]
	if p == "" {
		t.Fatal("GIT_CONFIG_GLOBAL must be exported so later discovers take effect")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("GIT_CONFIG_GLOBAL points at a file that does not exist: %v", err)
	}
	s := string(b)
	for _, want := range []string{"[include]", "path = ~/.gitconfig"} {
		if !strings.Contains(s, want) {
			t.Fatalf("zero-instance gitconfig missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "[credential") {
		t.Fatalf("nothing vaulted, so no credential section belongs here:\n%s", s)
	}
}

// GUARANTEE: a host of "{instance}" resolves per instance, so one directive
// covers every host discovery found (git's url-lines names each instance after
// the hostname) — and the substituted result is re-checked against the hostname
// charset, because instance names permit characters a section label does not.
func TestRenderOwnGitHelperSubstitutesInstanceHost(t *testing.T) {
	d := template.OwnDirective{
		Mechanism: template.MechGitCredentialHelper,
		Env:       "GIT_CONFIG_GLOBAL", File: "git.gitconfig", Host: "{instance}", Inherit: true,
	}
	r := renderOwn(d, "git", "akasha", "/d", []string{"github.com", "git.example.org", "under_score"})
	s := string(r.body)
	for _, want := range []string{
		`[credential "https://github.com"]`,
		"helper = !akasha helper git --instance github.com",
		`[credential "https://git.example.org"]`,
		"helper = !akasha helper git --instance git.example.org",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("substituted host body missing %q:\n%s", want, s)
		}
	}
	// Legal instance name, illegal hostname — dropped after substitution.
	if strings.Contains(s, "under_score") {
		t.Fatalf("non-hostname instance leaked into a host section:\n%s", s)
	}
}

// The merge: two git providers owning GIT_CONFIG_GLOBAL collapse into ONE
// gitconfig with both credential sections and a single [include], so github and
// gitlab broker in the same session instead of colliding on the env var.
func TestAssembleOwnershipMergesGitProviders(t *testing.T) {
	dir := t.TempDir()
	gh := template.OwnDirective{Mechanism: template.MechGitCredentialHelper, Env: "GIT_CONFIG_GLOBAL", File: "github.gitconfig", Host: "github.com", Inherit: true}
	gl := template.OwnDirective{Mechanism: template.MechGitCredentialHelper, Env: "GIT_CONFIG_GLOBAL", File: "gitlab.gitconfig", Host: "gitlab.com", Inherit: true}
	env, err := AssembleOwnership(dir, "/usr/bin/akasha", []OwnInput{
		{Provider: "github", Own: []template.OwnDirective{gh}, Instances: []string{"work"}},
		{Provider: "gitlab", Own: []template.OwnDirective{gl}, Instances: []string{"work"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := env["GIT_CONFIG_GLOBAL"]
	if filepath.Dir(p) != filepath.Clean(dir) {
		t.Fatalf("merged file not in dir: %q", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("merged file: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`[credential "https://github.com"]`,
		`[credential "https://gitlab.com"]`,
		"helper = !/usr/bin/akasha helper github --instance work",
		"helper = !/usr/bin/akasha helper gitlab --instance work",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("merged gitconfig missing %q:\n%s", want, s)
		}
	}
	if n := strings.Count(s, "[include]"); n != 1 {
		t.Fatalf("expected exactly one [include], got %d:\n%s", n, s)
	}
	// No per-provider orphan files — only the one merged file exists.
	if _, err := os.Stat(filepath.Join(dir, "github.gitconfig")); !os.IsNotExist(err) {
		t.Fatal("per-provider file should not be written when merged")
	}
}

// RenderOwnershipEnv is what `akasha exec --assume` calls to apply a provider's
// broker on demand: it must write the config file into the given dir and return
// the env that points the child's tooling at it. This is the exec broker path —
// the child resolves the secret through `akasha helper`, never via raw env.
func TestRenderOwnershipEnvWritesFileAndEnv(t *testing.T) {
	tpl := &template.Template{
		Name: "github",
		Agent: &template.AgentSpec{
			Own: []template.OwnDirective{{
				Mechanism: template.MechGitCredentialHelper,
				Env:       "GIT_CONFIG_GLOBAL",
				File:      "github.gitconfig",
				Host:      "github.com",
			}},
		},
	}
	dir := t.TempDir()
	env, err := RenderOwnershipEnv(tpl, "/usr/bin/akasha", dir, []string{"work"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "github.gitconfig")
	if env["GIT_CONFIG_GLOBAL"] != want {
		t.Fatalf("env should point at the rendered file: got %q want %q", env["GIT_CONFIG_GLOBAL"], want)
	}
	b, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("ownership file not written: %v", err)
	}
	if !strings.Contains(string(b), "helper = !/usr/bin/akasha helper github --instance work") {
		t.Fatalf("gitconfig must broker through akasha:\n%s", b)
	}
}

func TestRenderOwnershipEnvNilAgentIsNoOp(t *testing.T) {
	env, err := RenderOwnershipEnv(&template.Template{Name: "env"}, "akasha", t.TempDir(), []string{"x"})
	if err != nil || env != nil {
		t.Fatalf("no agent block → nil env, no error: env=%v err=%v", env, err)
	}
}

func TestRenderOwnDecoyWritesEmpty(t *testing.T) {
	d := template.OwnDirective{Mechanism: template.MechDecoy, Env: "AWS_SHARED_CREDENTIALS_FILE", File: "credentials.empty"}
	r := renderOwn(d, "aws", "akasha", "/d", nil)
	if !r.write || len(r.body) != 0 || len(r.preamble) != 0 {
		t.Fatalf("decoy should write an empty file: write=%v body=%d preamble=%d", r.write, len(r.body), len(r.preamble))
	}
}
