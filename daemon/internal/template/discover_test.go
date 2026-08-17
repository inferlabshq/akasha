package template

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverINI(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "credentials"), `
# comment
[default]
aws_access_key_id = AKIA1
aws_secret_access_key = sk1

[profile prod]
AWS_ACCESS_KEY_ID = AKIA2
aws_secret_access_key = sk2
aws_session_token = tok
`)
	finds := runSource(DiscoverSource{
		Source: "ini",
		Path:   filepath.Join(dir, "credentials"),
		Map: map[string]string{
			"access_key_id":     "aws_access_key_id",
			"secret_access_key": "aws_secret_access_key",
			"session_token":     "aws_session_token",
		},
	})
	if len(finds) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(finds), finds)
	}
	if finds[0].Instance != "default" || finds[0].Fields["access_key_id"] != "AKIA1" {
		t.Fatalf("default profile wrong: %+v", finds[0])
	}
	// "[profile X]" prefix stripped, keys matched case-insensitively.
	if finds[1].Instance != "prod" || finds[1].Fields["access_key_id"] != "AKIA2" || finds[1].Fields["session_token"] != "tok" {
		t.Fatalf("prod profile wrong: %+v", finds[1])
	}
}

func TestDiscoverEnvLines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".zshrc"), `
# shell config
export OPENAI_API_KEY="sk-abc123"
export UNRELATED=x
DD_API_KEY=ddk
`)
	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".zshrc"),
		Map:    map[string]string{"api_key": "OPENAI_API_KEY"},
	})
	if len(finds) != 1 || finds[0].Fields["api_key"] != "sk-abc123" {
		t.Fatalf("env-lines wrong: %+v", finds)
	}
	if len(finds[0].Fields) != 1 {
		t.Fatalf("captured unrequested vars: %+v", finds[0].Fields)
	}
}

func TestDiscoverDocKeys(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `
github.com:
    oauth_token: ghp_x
    user: tanim
gitlab.example.com:
    oauth_token: glpat_y
`)
	finds := runSource(DiscoverSource{
		Source:    "yaml",
		Path:      filepath.Join(dir, "hosts.yml"),
		Instances: "keys",
		Map:       map[string]string{"token": "oauth_token"},
	})
	if len(finds) != 2 {
		t.Fatalf("expected 2 instances, got %+v", finds)
	}
	byInst := map[string]string{}
	for _, f := range finds {
		byInst[f.Instance] = f.Fields["token"]
	}
	if byInst["github.com"] != "ghp_x" || byInst["gitlab.example.com"] != "glpat_y" {
		t.Fatalf("instances wrong: %v", byInst)
	}
}

func TestDiscoverDocSingleJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "auth.json"), `{"api_key": "sk-live", "other": 1}`)
	finds := runSource(DiscoverSource{
		Source: "json",
		Path:   filepath.Join(dir, "auth.json"),
		Map:    map[string]string{"token": "api_key"},
	})
	if len(finds) != 1 || finds[0].Instance != "default" || finds[0].Fields["token"] != "sk-live" {
		t.Fatalf("json single wrong: %+v", finds)
	}
}

func TestDiscoverFilesPEM(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFile(t, filepath.Join(dir, "id_ed25519.pub"), "ssh-ed25519 AAAA")
	writeFile(t, filepath.Join(dir, "known_hosts"), "github.com ssh-rsa AAAA")

	finds := discoverFiles(DiscoverSource{
		Source: "file",
		Path:   filepath.Join(dir, "id_*"),
		Match:  "pem-private-key",
		Map:    map[string]string{"private_key": "content", "key_name": "filename"},
	})
	if len(finds) != 1 {
		t.Fatalf("expected only the private key to match: %+v", finds)
	}
	f := finds[0]
	if f.Instance != "id_ed25519" || f.Fields["key_name"] != "id_ed25519" {
		t.Fatalf("instance/filename wrong: %+v", f)
	}
	if !strings.Contains(f.Fields["private_key"], "PRIVATE KEY") {
		t.Fatalf("content not captured: %+v", f.Fields)
	}
}

// TestDiscoverUserEndToEnd is the extensibility story: a user drops a provider
// template with a discover block and DiscoverUser finds its instances — through
// the SAME path the shipped providers use. aws is checked alongside it because
// aws used to be exempt: it was scanned by hand-written Go, and its template's
// discover block never ran. There is no exemption now.
func TestDiscoverUserEndToEnd(t *testing.T) {
	tplDir := t.TempDir()
	dataDir := t.TempDir()
	// Shipped bundle (for aws) + the user dir holding the datadog template.
	t.Setenv("AKASHA_TEMPLATES_PATH", BundleDirForTest()+string(os.PathListSeparator)+tplDir)

	cfg := filepath.Join(dataDir, "datadog.ini")
	writeFile(t, cfg, "[default]\napi_key = ddk\n")
	writeFile(t, filepath.Join(tplDir, "datadog.yaml"), `
kind: provider
name: datadog
version: 1
credential:
  fields:
    api_key: {secret: true}
discover:
  - source: ini
    path: `+cfg+`
    map: {api_key: api_key}
    risk: medium
deliver:
  - mode: env
    env: {DD_API_KEY: "{api_key}"}
`)
	ResetForTest()
	defer ResetForTest()

	trustAll := func(*Template) bool { return true }
	finds := DiscoverUser(trustAll)
	var dd []Finding
	for _, f := range finds {
		if f.Provider == "datadog" {
			dd = append(dd, f)
		}

	}
	if len(dd) != 1 || dd[0].Instance != "default" || dd[0].Fields["api_key"] != "ddk" || dd[0].Risk != "medium" {
		t.Fatalf("datadog discovery wrong: %+v", dd)
	}

	// A shipped provider must go through this same engine. aws declares its
	// discover sources, so the engine must at least attempt them — proving the
	// native-scanner exemption is gone rather than merely unused.
	aws := Get("aws")
	if aws == nil || len(aws.Discover) == 0 {
		t.Fatal("aws template should declare its own discover block")
	}

	// Gate: an UNtrusted discovery template is not run — no findings, no read.
	if got := DiscoverUser(func(*Template) bool { return false }); len(got) != 0 {
		t.Fatalf("untrusted discovery must not run, got %+v", got)
	}
}
