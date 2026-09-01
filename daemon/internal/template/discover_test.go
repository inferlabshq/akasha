package template

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// A named pipe on a scanned path used to hang discovery forever: os.Open blocks
// on a fifo until a writer appears, and every parser opens what it is handed.
// One stray pipe in a home directory wedged `akasha discover` AND `akasha setup`
// with no output at all — `--dry-run` included, so the read-only command was no
// safer. Both glob expansion and the file source are covered, because they run
// separate globs and only one of them was ever type-checked.
func TestDiscoverSkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hang.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	// A symlink pointing AT the fifo: following the link must not reintroduce
	// the block that the direct case now avoids.
	viaLink := filepath.Join(dir, "link.fifo")
	if err := os.Symlink(fifo, viaLink); err != nil {
		t.Fatal(err)
	}
	awsMap := map[string]string{
		"access_key_id":     "aws_access_key_id",
		"secret_access_key": "aws_secret_access_key",
	}

	cases := []struct {
		name string
		run  func() []Finding
	}{
		// The literal path is the case a glob-only fix would miss: the aws
		// template names its config file outright, with no metacharacter to
		// filter on.
		{"ini literal", func() []Finding {
			return runSource(DiscoverSource{Source: "ini", Path: fifo, Map: awsMap})
		}},
		{"ini glob", func() []Finding {
			return runSource(DiscoverSource{Source: "ini", Path: filepath.Join(dir, "*.fifo"), Map: awsMap})
		}},
		{"env-lines glob", func() []Finding {
			return runSource(DiscoverSource{Source: "env-lines", Path: filepath.Join(dir, "*.fifo"),
				Map: map[string]string{"access_key_id": "AWS_ACCESS_KEY_ID"}})
		}},
		{"url-lines literal", func() []Finding {
			return runSource(DiscoverSource{Source: "url-lines", Path: fifo,
				Map: map[string]string{"token": "password"}})
		}},
		{"symlink to fifo", func() []Finding {
			return runSource(DiscoverSource{Source: "ini", Path: viaLink, Map: awsMap})
		}},
		// The ssh template ships `source: file` over an id_* glob, so a fifo
		// named id_anything reached this open. discoverFiles globs independently
		// of globbed() and filtered on IsDir(), which admits fifos.
		{"file source glob", func() []Finding {
			return discoverFiles(DiscoverSource{Source: "file", Path: filepath.Join(dir, "*.fifo"),
				Map: map[string]string{"private_key": "content"}})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan []Finding, 1)
			go func() { done <- tc.run() }()
			select {
			case finds := <-done:
				if len(finds) != 0 {
					t.Fatalf("a fifo must yield nothing, got %+v", finds)
				}
			case <-time.After(5 * time.Second):
				// Deliberately not reporting from the goroutine: the read is
				// blocked in the kernel and will never return to report itself.
				t.Fatal("discovery blocked on a non-regular file — the hang is back")
			}
		})
	}
}

// The guard tests the TARGET of a symlink, not the link. Anyone using chezmoi,
// GNU stow or a dotfiles repo has their credential files symlinked, and
// rejecting links outright would silently stop discovering them — trading a
// hang for a wrong answer.
func TestDiscoverFollowsSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-creds")
	writeFile(t, real, "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = sk1\n")
	link := filepath.Join(dir, "linked-creds")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	finds := runSource(DiscoverSource{Source: "ini", Path: link, Map: map[string]string{
		"access_key_id":     "aws_access_key_id",
		"secret_access_key": "aws_secret_access_key",
	}})
	if len(finds) != 1 || finds[0].Fields["access_key_id"] != "AKIA1" {
		t.Fatalf("a symlink to a regular file must still be discovered: %+v", finds)
	}

	// A dangling link resolves to nothing and must be skipped, not fatal.
	dangling := filepath.Join(dir, "gone")
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), dangling); err != nil {
		t.Fatal(err)
	}
	if finds := runSource(DiscoverSource{Source: "ini", Path: dangling, Map: map[string]string{
		"access_key_id": "aws_access_key_id",
	}}); len(finds) != 0 {
		t.Fatalf("a dangling symlink must yield nothing: %+v", finds)
	}
}

// A single-quoted value is a shell LITERAL: `KEY='$ecret'` is the six
// characters after the quote, not a reference to anything. Blanking it produced
// exactly the half credential the parser was loosened to stop — one field of a
// pair vaulted, the other silently dropped, failing at first use with nothing to
// look at. A leading `$` is ordinary in a generated passphrase.
func TestEnvLinesKeepsLiteralDollarInsideSingleQuotes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), strings.Join([]string{
		`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
		`AWS_SECRET_ACCESS_KEY='$ecretLiteralPassphrase'`,
	}, "\n")+"\n")

	finds := runSource(DiscoverSource{Source: "env-lines", Path: filepath.Join(dir, ".env"), Map: map[string]string{
		"access_key_id":     "AWS_ACCESS_KEY_ID",
		"secret_access_key": "AWS_SECRET_ACCESS_KEY",
	}})
	if len(finds) != 1 {
		t.Fatalf("expected one finding, got %+v", finds)
	}
	if got := finds[0].Fields["secret_access_key"]; got != "$ecretLiteralPassphrase" {
		t.Fatalf("single-quoted literal was mangled: %q", got)
	}
}

// The other half of the rule, which is what makes it a rule and not a hole:
// double quotes and no quotes both expand in a shell, so a `$` there really can
// be a reference to a credential rather than one.
func TestEnvLinesStillDropsExpansions(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, line string }{
		{"unquoted var", `AWS_SECRET_ACCESS_KEY=$AWS_REAL_SECRET`},
		{"double-quoted var", `AWS_SECRET_ACCESS_KEY="$AWS_REAL_SECRET"`},
		{"command substitution", `AWS_SECRET_ACCESS_KEY="$(pass aws)"`},
		{"backtick", "AWS_SECRET_ACCESS_KEY=`pass aws`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".env")
			writeFile(t, p, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"+tc.line+"\n")
			finds := runSource(DiscoverSource{Source: "env-lines", Path: p, Map: map[string]string{
				"access_key_id":     "AWS_ACCESS_KEY_ID",
				"secret_access_key": "AWS_SECRET_ACCESS_KEY",
			}})
			if len(finds) == 1 {
				if v, ok := finds[0].Fields["secret_access_key"]; ok {
					t.Fatalf("a reference was vaulted as a value: %q", v)
				}
			}
		})
	}
}

// A partial credential must not take a name from a usable one.
//
// The shape is ordinary: a project .env exporting AWS_ACCESS_KEY_ID and nothing
// else, ranked ABOVE the shell config that holds the complete pair. Ranked by
// declared order alone the half won, discovery printed "✓ vaulted", and the
// first `akasha helper aws` failed with `missing required field
// "secret_access_key"` — a credential that never had a chance of working,
// chosen over one that did, with the working copy discarded.
func TestPartialCredentialDoesNotShadowAUsableOne(t *testing.T) {
	half := Finding{
		Provider: "aws", Instance: "default", Source: "~/.env",
		Fields: map[string]string{"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
	}
	complete := Finding{
		Provider: "aws", Instance: "default", Source: "~/.zshrc",
		Fields: map[string]string{
			"access_key_id":     "AKIAIOSFODNN7EXAMPL2",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYCOMPLETE",
		},
	}

	// The half is declared FIRST, which is exactly the losing case.
	got := resolveLabels([]Finding{half, complete})
	if len(got) != 1 {
		t.Fatalf("expected one credential for aws:default, got %d", len(got))
	}
	if got[0].Source != "~/.zshrc" {
		t.Fatalf("the partial copy took the name: winner is %s, want ~/.zshrc", got[0].Source)
	}
	if got[0].Incomplete {
		t.Error("a complete winner must not be flagged incomplete")
	}
	if len(got[0].Shadowed) != 1 || got[0].Shadowed[0] != "~/.env" {
		t.Errorf("the discarded copy should be disclosed, got %v", got[0].Shadowed)
	}
	// The winner must actually resolve — the whole point.
	if _, err := Get("aws").ResolveCreds(got[0].Fields); err != nil {
		t.Errorf("the vaulted credential still cannot be used: %v", err)
	}
}

// Declared order still decides among credentials that all work: completeness
// breaks ties, it does not replace the precedence a template author chose.
func TestDeclaredOrderStillWinsAmongUsableCredentials(t *testing.T) {
	first := Finding{
		Provider: "aws", Instance: "default", Source: "~/.aws/creds",
		Fields: map[string]string{"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "s1"},
	}
	// The second candidate carries MORE fields than the first, so a rule that
	// ranked by completeness rather than using it as a tie-break would pick it.
	// That is not a hypothetical: aws declares session_token optional, and the
	// richer finding is typically the ephemeral one — an assume-role session in
	// a .env that expires within the hour, taking a permanent name from the
	// durable pair in the credentials file. Equal field counts on both sides
	// made this test unable to tell the two rules apart.
	second := Finding{
		Provider: "aws", Instance: "default", Source: "~/.zshrc",
		Fields: map[string]string{
			"access_key_id": "AKIAIOSFODNN7EXAMPL2", "secret_access_key": "s2",
			"session_token": "ephemeral-and-expiring",
		},
	}
	got := resolveLabels([]Finding{first, second})
	if len(got) != 1 || got[0].Source != "~/.aws/creds" {
		t.Fatalf("declared order should decide between two usable credentials, got %+v", got)
	}
}

// When nothing found under the name is complete, the first is still offered —
// there is nothing better to pick and a silent absence is not actionable — but
// it is FLAGGED, so "✓ vaulted" is not the last thing the user hears about it.
func TestAllPartialKeepsTheFirstAndFlagsIt(t *testing.T) {
	a := Finding{Provider: "aws", Instance: "default", Source: "~/.env",
		Fields: map[string]string{"access_key_id": "AKIAIOSFODNN7EXAMPLE"}}
	b := Finding{Provider: "aws", Instance: "default", Source: "~/.zshrc",
		Fields: map[string]string{"access_key_id": "AKIAIOSFODNN7EXAMPL2"}}

	got := resolveLabels([]Finding{a, b})
	if len(got) != 1 || got[0].Source != "~/.env" {
		t.Fatalf("expected the first partial to stand, got %+v", got)
	}
	if !got[0].Incomplete {
		t.Error("a credential that cannot authenticate must be flagged incomplete")
	}
}

// A provider Akasha has no template for has no notion of completeness, so it
// must never be demoted — env: labels hold arbitrary secrets by design.
func TestUnknownProviderIsNeverDemoted(t *testing.T) {
	a := Finding{Provider: "env", Instance: "stripe", Source: "~/.env",
		Fields: map[string]string{"anything": "sk_live_x"}}
	b := Finding{Provider: "env", Instance: "stripe", Source: "~/.zshrc",
		Fields: map[string]string{"anything": "sk_live_y"}}
	got := resolveLabels([]Finding{a, b})
	if len(got) != 1 || got[0].Source != "~/.env" || got[0].Incomplete {
		t.Fatalf("an unknown provider must keep declared order and no flag, got %+v", got)
	}
}

// filename-stem drops the extension, so a provider whose credentials are *.json
// gets "prod" rather than "prod.json" (and a session file named azure-prod.json
// rather than azure-prod.json.json).
func TestFilenameStemDropsTheExtension(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"prod.json", "prod"},
		{"id_ed25519", "id_ed25519"}, // no extension: unchanged
		{"my.key.json", "my.key"},    // only the last one goes
		{".pgpass", ".pgpass"},       // a dotfile is a name, not an extension
		{"archive.tar.gz", "archive.tar"},
	} {
		if got := stripExt(c.in); got != c.want {
			t.Errorf("stripExt(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The existing `filename` behaviour is untouched — ssh relies on it.
func TestFilenameInstancesStillKeepsTheWholeName(t *testing.T) {
	d := DiscoverSource{Instances: "filename"}
	if got := instanceName(d, "/home/dev/.ssh/id_ed25519"); got != "id_ed25519" {
		t.Errorf("instanceName = %q, want id_ed25519", got)
	}
	d.Instances = "filename-stem"
	if got := instanceName(d, "/home/dev/.azure/prod.json"); got != "prod" {
		t.Errorf("instanceName = %q, want prod", got)
	}
}
