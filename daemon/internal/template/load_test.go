package template

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUserDirDropIn covers the whole extensibility promise under the
// no-builtins model: a YAML file dropped into the user dir becomes a working
// provider, a file whose name matches a shipped one OVERRIDES it (there is no
// privileged tier), and an invalid file is skipped — each with a logged reason.
func TestUserDirDropIn(t *testing.T) {
	userDir := t.TempDir()
	// Search path = shipped bundle first, then the user dir (which overrides).
	t.Setenv("AKASHA_TEMPLATES_PATH", BundleDirForTest()+string(os.PathListSeparator)+userDir)

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(userDir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("datadog.yaml", `
kind: provider
name: datadog
version: 1
credential:
  fields:
    api_key: {secret: true}
    app_key: {secret: true, optional: true}
deliver:
  - mode: env
    env:
      DD_API_KEY: "{api_key}"
      DD_APP_KEY: "{app_key}"
`)
	// A user file named "aws" — under the no-builtins model this OVERRIDES the
	// shipped aws template rather than being rejected.
	write("aws.yaml", `
kind: provider
name: aws
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {MINE: "{k}"}}]
`)
	write("broken.yaml", `kind: provider`)

	var logged []string
	oldLogf := Logf
	Logf = func(format string, args ...interface{}) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	defer func() { Logf = oldLogf }()

	ResetForTest()
	defer ResetForTest()

	// Drop-in provider works end to end.
	dd := Get("datadog")
	if dd == nil {
		t.Fatal("user template not loaded")
	}
	if !strings.HasPrefix(dd.Origin(), userDir) {
		t.Fatalf("datadog origin should be in the user dir, got %q", dd.Origin())
	}
	r, err := dd.Render("default", map[string]string{"api_key": "ddk"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Env["DD_API_KEY"] != "ddk" {
		t.Fatalf("env = %v", r.Env)
	}
	if _, ok := r.Env["DD_APP_KEY"]; ok {
		t.Fatal("unset optional field should drop the env entry")
	}

	// User aws overrides the shipped one: the loaded aws is the user's file.
	aws := Get("aws")
	if !strings.HasPrefix(aws.Origin(), userDir) {
		t.Fatalf("user aws should override the shipped one, origin = %q", aws.Origin())
	}
	if aws.EnvDeliver() == nil || aws.EnvDeliver().Env["MINE"] == "" {
		t.Fatal("loaded aws is not the user override")
	}

	all := strings.Join(logged, "\n")
	for _, want := range []string{"capabilities", "overrides", "broken.yaml"} {
		if !strings.Contains(all, want) {
			t.Fatalf("expected log containing %q, got:\n%s", want, all)
		}
	}
}

// TestDigestIsOfTheBytesParsedFrom pins the binding the trust gate rests on: a
// loaded template carries the SHA-256 of the exact bytes it was parsed from,
// and rewriting the file underneath it does not change that digest until a
// reload. Parse (the authoring path) sets no digest, just as it sets no origin.
func TestDigestIsOfTheBytesParsedFrom(t *testing.T) {
	body := `
kind: provider
name: acme
version: 1
credential: {fields: {token: {secret: true}}}
deliver: [{mode: env, env: {ACME: "{token}"}}]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	ResetForTest()
	defer ResetForTest()

	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])

	tpl := Get("acme")
	if tpl == nil {
		t.Fatal("acme failed to load")
	}
	if tpl.Digest() != want {
		t.Fatalf("digest = %q, want the hash of the loaded bytes %q", tpl.Digest(), want)
	}

	if err := os.WriteFile(path, []byte(body+"\n# rewritten under the loaded template\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if tpl.Digest() != want {
		t.Fatalf("digest = %q after the file changed; it must describe the bytes in use, not the file", tpl.Digest())
	}

	parsed, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest() != "" || parsed.Origin() != "" {
		t.Fatalf("Parse must leave provenance unset, got digest=%q origin=%q", parsed.Digest(), parsed.Origin())
	}
}
