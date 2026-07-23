package resolve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
)

// fakeOp writes a stand-in `op` binary that records its argv and env to
// sidecar files and prints `output` on stdout. Returns its path.
func fakeOp(t *testing.T, output string) (bin, argsFile, envFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "op")
	argsFile = filepath.Join(dir, "args")
	envFile = filepath.Join(dir, "env")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + argsFile + "\n" +
		"env > " + envFile + "\n" +
		"printf '%s' '" + output + "'\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile, envFile
}

func opSpec() template.SourceSpec {
	return template.SourceSpec{
		Backend: "onepassword-cli",
		Ref:     "op://Eng/datadog/{instance}/credential",
		Map:     map[string]string{"value": "api_key"},
	}
}

func TestResolveOnePassword(t *testing.T) {
	bin, argsFile, envFile := fakeOp(t, "s3cr3t-value")
	t.Setenv("AKASHA_OP_BIN", bin)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "tok-123")
	t.Setenv("SECRET_LEAK", "do-not-pass")     // must be scrubbed
	t.Setenv("AKASHA_AGENT_KEY", "agentkey")   // must be scrubbed

	got, err := resolveSpec(context.Background(), opSpec(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if got["api_key"] != "s3cr3t-value" {
		t.Fatalf("api_key = %q", got["api_key"])
	}

	// argv: ref substituted, passed after "--" (no shell, no flag injection).
	args, _ := os.ReadFile(argsFile)
	wantArgs := "read\n--no-newline\n--\nop://Eng/datadog/default/credential\n"
	if string(args) != wantArgs {
		t.Fatalf("argv = %q, want %q", args, wantArgs)
	}

	// env: only the allowlist reaches the subprocess.
	env, _ := os.ReadFile(envFile)
	es := string(env)
	if !strings.Contains(es, "OP_SERVICE_ACCOUNT_TOKEN=tok-123") {
		t.Fatal("allowlisted OP_SERVICE_ACCOUNT_TOKEN should be passed")
	}
	if strings.Contains(es, "SECRET_LEAK") || strings.Contains(es, "AKASHA_AGENT_KEY") {
		t.Fatalf("non-allowlisted env leaked to the subprocess:\n%s", es)
	}
}

func TestResolveMissingBinary(t *testing.T) {
	t.Setenv("AKASHA_OP_BIN", filepath.Join(t.TempDir(), "nope"))
	if _, err := resolveSpec(context.Background(), opSpec(), "default"); err == nil {
		t.Fatal("a missing binary should error")
	}
}

func TestResolveRejectsRelativeBin(t *testing.T) {
	t.Setenv("AKASHA_OP_BIN", "op") // not absolute
	if _, err := resolveSpec(context.Background(), opSpec(), "default"); err == nil {
		t.Fatal("a non-absolute AKASHA_OP_BIN must be rejected")
	}
}

// A world-writable binary is the PATH-hijack vector — refuse it.
func TestResolveRejectsWorldWritableBin(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "op")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf x\n"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o777); err != nil { // ensure world-writable bit set
		t.Fatal(err)
	}
	t.Setenv("AKASHA_OP_BIN", bin)
	_, err := resolveSpec(context.Background(), opSpec(), "default")
	if err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable binary should be refused, got: %v", err)
	}
}

func TestResolveTemplateTrustGate(t *testing.T) {
	bin, _, _ := fakeOp(t, "fetched")
	t.Setenv("AKASHA_OP_BIN", bin)
	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	// A source template loaded through the registry (so it has an Origin).
	dir := t.TempDir()
	doc := `
kind: provider
name: datadog
version: 1
credential: {fields: {api_key: {secret: true}}}
source:
  - backend: onepassword-cli
    ref: "op://Eng/datadog/{instance}/credential"
    map: {value: api_key}
deliver: [{mode: env, env: {DD_API_KEY: "{api_key}"}}]
`
	os.WriteFile(filepath.Join(dir, "datadog.yaml"), []byte(doc), 0600)
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)
	tpl := template.Get("datadog")
	if tpl == nil {
		t.Fatal("template not loaded")
	}

	store, _ := trust.Load()

	// Untrusted → refused (running a backend requires approval).
	if _, err := ResolveTemplate(context.Background(), store, tpl, 0, "default"); err == nil {
		t.Fatal("resolving an untrusted source template must be refused")
	}

	// Approve, then it resolves.
	if err := store.Approve(tpl); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveTemplate(context.Background(), store, tpl, 0, "default")
	if err != nil {
		t.Fatal(err)
	}
	if got["api_key"] != "fetched" {
		t.Fatalf("api_key = %q", got["api_key"])
	}
}
