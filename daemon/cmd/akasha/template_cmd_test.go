package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

func TestExplainGitHubOwnership(t *testing.T) {
	tpl := template.Get("github")
	if tpl == nil {
		t.Fatal("github template not loaded")
	}
	var buf bytes.Buffer
	explainTemplate(&buf, tpl)
	out := buf.String()

	for _, want := range []string{
		"owns agent session env: GIT_CONFIG_GLOBAL",
		"helper (kv-lines)",
		"[include]",
		"path = ~/.gitconfig",
		`[credential "https://github.com"]`,
		"helper = !akasha helper github --instance default",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain output missing %q:\n%s", want, out)
		}
	}
	// Placeholder secrets only — a real-looking secret must never appear.
	if strings.Contains(out, "ghp_") {
		t.Fatalf("explain leaked a non-placeholder value:\n%s", out)
	}
}

func TestExplainAWSFileRender(t *testing.T) {
	tpl := template.Get("aws")
	if tpl == nil {
		t.Fatal("aws template not loaded")
	}
	var buf bytes.Buffer
	explainTemplate(&buf, tpl)
	out := buf.String()
	for _, want := range []string{
		"reads:",
		"~/.aws/credentials (ini)",
		"file \"aws-default.creds\"",
		"[default]",
		"aws_access_key_id = <access_key_id>",
		"credential_process = akasha helper aws --instance default",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain output missing %q:\n%s", want, out)
		}
	}
}

func TestParseTemplateFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte("kind: provider\nname: x\nversion: 1\ncredential: {fields: {k: {secret: true}}}\ndeliver: [{mode: env, env: {K: \"{k}\"}}]\n"), 0600)
	if _, err := parseTemplateFile(good); err != nil {
		t.Fatalf("good template should parse: %v", err)
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("kind: provider\nname: x\nversion: 1\ncredential: {fields: {k: {secret: true}}}\ndeliver: [{mode: pipe}]\n"), 0600)
	if _, err := parseTemplateFile(bad); err == nil {
		t.Fatal("bad template should fail to parse")
	}

	if _, err := parseTemplateFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestLoadTemplateArg(t *testing.T) {
	// By name (loaded builtin).
	if tpl, err := loadTemplateArg("github"); err != nil || tpl == nil {
		t.Fatalf("loadTemplateArg(github) = %v, %v", tpl, err)
	}
	// Unknown name, not a file.
	if _, err := loadTemplateArg("definitely-not-a-template-xyz"); err == nil {
		t.Fatal("unknown arg should error")
	}
	// By file path takes precedence over name lookup.
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte("kind: provider\nname: custom\nversion: 1\ncredential: {fields: {k: {secret: true}}}\ndeliver: [{mode: env, env: {K: \"{k}\"}}]\n"), 0600)
	tpl, err := loadTemplateArg(path)
	if err != nil || tpl.Name != "custom" {
		t.Fatalf("loadTemplateArg(file) = %v, %v", tpl, err)
	}
}

// The scaffold `akasha template new` prints must itself be a valid plugin —
// otherwise authors start from a broken file.
func TestSkeletonIsValid(t *testing.T) {
	doc := fmt.Sprintf(templateSkeleton, "vercel", "vercel")
	tpl, err := template.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("scaffold does not parse: %v", err)
	}
	if tpl.Name != "vercel" || tpl.Kind != template.KindProvider {
		t.Fatalf("scaffold wrong shape: %+v", tpl)
	}
}
