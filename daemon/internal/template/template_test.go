package template

import (
	"strings"
	"testing"
)

// ─── Bundle loading ─────────────────────────────────────────────────────────

func TestBundleAWSLoads(t *testing.T) {
	tpl := Get("aws")
	if tpl == nil {
		t.Fatal("bundled aws template not loaded")
	}
	if !strings.HasSuffix(tpl.Origin(), "aws.yaml") {
		t.Fatalf("aws origin should point at the loaded file, got %q", tpl.Origin())
	}
	if tpl.Kind != KindProvider {
		t.Fatalf("kind = %q", tpl.Kind)
	}
	if tpl.FileDeliver() == nil {
		t.Fatal("aws must declare a file deliver mode")
	}
	if tpl.Mint == nil || tpl.Mint.Contract != "aws-sts-session-policy" {
		t.Fatal("aws must declare the STS mint contract")
	}
}

// ─── Render: parity with the old hand-written AWS writer ───────────────────

func TestRenderAWSFile(t *testing.T) {
	tpl := Get("aws")
	r, err := tpl.Render("default", map[string]string{
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secretvalue123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.FileName != "aws-default.creds" {
		t.Fatalf("file name = %q", r.FileName)
	}
	body := string(r.Body)
	want := "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secretvalue123\n"
	if body != want {
		t.Fatalf("body:\n%q\nwant:\n%q", body, want)
	}
	if err := r.ResolveEnv("/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if r.Env["AWS_SHARED_CREDENTIALS_FILE"] != "/tmp/x" || r.Env["AWS_PROFILE"] != "default" {
		t.Fatalf("env = %v", r.Env)
	}
}

func TestRenderAWSSessionToken(t *testing.T) {
	tpl := Get("aws")
	r, err := tpl.Render("prod", map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sk",
		"session_token":     "tok123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.Body), "aws_session_token = tok123") {
		t.Fatalf("session token line missing:\n%s", r.Body)
	}
}

func TestRenderAWSOmitsUnsetOptionalLine(t *testing.T) {
	tpl := Get("aws")
	r, err := tpl.Render("default", map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sk",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Body), "session_token") {
		t.Fatalf("unset optional field leaked into render:\n%s", r.Body)
	}
}

func TestRenderMissingRequiredField(t *testing.T) {
	tpl := Get("aws")
	if _, err := tpl.Render("default", map[string]string{"access_key_id": "only"}); err == nil {
		t.Fatal("expected error for missing secret_access_key")
	}
}

func TestRenderIgnoresUndeclaredCreds(t *testing.T) {
	tpl := Get("aws")
	r, err := tpl.Render("default", map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sk",
		"sneaky_extra":      "should-not-appear",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Body), "should-not-appear") {
		t.Fatal("undeclared credential key leaked into render")
	}
}

// ─── Aliases ────────────────────────────────────────────────────────────────

func TestResolveCredsAliases(t *testing.T) {
	gh := Get("github")
	// Single-value label stores under "value"; alias resolves it to token.
	r, err := gh.Render("x", map[string]string{"value": "ghp_abc"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Env["GITHUB_TOKEN"] != "ghp_abc" {
		t.Fatalf("alias not resolved: %v", r.Env)
	}
	// Declared field name wins over its alias.
	r, _ = gh.Render("x", map[string]string{"token": "real", "value": "stale"})
	if r.Env["GITHUB_TOKEN"] != "real" {
		t.Fatalf("field should win over alias: %v", r.Env)
	}
	// Neither present → required error.
	if _, err := gh.Render("x", map[string]string{}); err == nil {
		t.Fatal("expected missing-field error")
	}
}

func TestParseRejectsAliasCollision(t *testing.T) {
	doc := `
kind: provider
name: x
version: 1
credential:
  fields:
    token: {secret: true, aliases: [other]}
    other: {secret: true}
deliver: [{mode: env, env: {K: "{token}"}}]`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("expected alias/field collision error")
	}
}

// ─── Substitution ───────────────────────────────────────────────────────────

func TestSubstUnknownPlaceholder(t *testing.T) {
	if _, err := Subst("hello {nope}", map[string]string{"x": "1"}); err == nil {
		t.Fatal("expected unknown-placeholder error")
	}
}

func TestSubstNoLogic(t *testing.T) {
	// Anything that isn't a plain lowercase identifier is not a placeholder:
	// the "language" must not accidentally grow syntax.
	for _, s := range []string{"{a.b}", "{a|b}", "{A}", "{ x }", "{{x}}"} {
		out, err := Subst(s, map[string]string{"x": "1", "a": "1"})
		if err != nil {
			continue // {{x}} contains valid {x}; others must pass through
		}
		if s == "{{x}}" {
			if out != "{1}" {
				t.Fatalf("brace nesting: got %q", out)
			}
			continue
		}
		if out != s {
			t.Fatalf("non-placeholder %q was rewritten to %q", s, out)
		}
	}
}

// ─── Parse + validation ─────────────────────────────────────────────────────

const minimalProvider = `
kind: provider
name: stripe
version: 1
credential:
  fields:
    api_key: {secret: true}
deliver:
  - mode: env
    env: {STRIPE_API_KEY: "{api_key}"}
`

func TestParseMinimalProvider(t *testing.T) {
	tpl, err := Parse([]byte(minimalProvider))
	if err != nil {
		t.Fatal(err)
	}
	r, err := tpl.Render("default", map[string]string{"api_key": "sk_live_x"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Env["STRIPE_API_KEY"] != "sk_live_x" || r.FileName != "" {
		t.Fatalf("env-only render wrong: %+v", r)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown top-level key": `
kind: provider
name: x
version: 1
bogus: true
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]`,
		"unknown deliver mode": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: pipe, env: {K: "{k}"}}]`,
		"unknown contract": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, contract: my-custom-thing}]`,
		"render references undeclared field": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - mode: file
    name: "x-{instance}.creds"
    render: ["{other}"]`,
		"agent own unknown mechanism": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
agent:
  own: [{mechanism: run-anything, env: X, file: x.conf}]`,
		"agent own section tries to break ini structure": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
agent:
  own:
    - mechanism: credential-process
      env: AWS_CONFIG_FILE
      file: x.conf
      section: "profile x]\ncredential_process = /bin/sh -c evil\n[junk"`,
		"agent own git host injection": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
agent:
  own: [{mechanism: git-credential-helper, env: GIT_CONFIG_GLOBAL, file: g, host: "evil.com\n[credential] helper = !sh"}]`,
		"bad version": `
kind: provider
name: x
version: 2
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]`,
		"bad name": `
kind: provider
name: "../evil"
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]`,
		"unknown mint contract": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
mint: {contract: do-anything}`,
		"unknown source backend": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
source: [{backend: my-vault, ref: "x", map: {out: k}}]`,
		"source maps to unknown field": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
source: [{backend: onepassword-cli, ref: "op://v/i/f", map: {out: nope}}]`,
		"source ref references unknown param": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
source: [{backend: onepassword-cli, ref: "op://v/{bogus}/f", map: {out: k}}]`,
		"agent own missing required param": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
agent:
  own: [{mechanism: credential-process, env: AWS_CONFIG_FILE, file: x.conf}]`,
		"discovery with deliver block": `
kind: discovery
name: x
version: 1
provider: aws
discover: [{source: ini, path: ~/x}]
deliver: [{mode: env, env: {K: "v"}}]`,
		"discovery without provider": `
kind: discovery
name: x
version: 1
discover: [{source: ini, path: ~/x}]`,
		"unknown kind": `
kind: gadget
name: x
version: 1`,
	}
	for label, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected parse/validate error", label)
		}
	}
}

func TestSourceParsesAndIsSensitive(t *testing.T) {
	doc := `
kind: provider
name: datadog
version: 1
credential: {fields: {api_key: {secret: true}}}
source:
  - backend: onepassword-cli
    mode: on-demand
    ref: "op://{vault}/datadog/{instance}/credential"
    params: {vault: Eng}
    map: {password: api_key}
    cache: {ttl: 120}
deliver:
  - mode: env
    env: {DD_API_KEY: "{api_key}"}
`
	tpl, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("valid source template should parse: %v", err)
	}
	if len(tpl.Source) != 1 || tpl.Source[0].Backend != "onepassword-cli" {
		t.Fatalf("source not parsed: %+v", tpl.Source)
	}
	// A source means the template runs a backend, and it also delivers a
	// credential — both are sensitive, so both gate.
	caps := tpl.SensitiveCapabilities()
	got := map[string]bool{}
	for _, c := range caps {
		got[c] = true
	}
	if !got[CapRunBackend] || !got[CapDeliver] {
		t.Fatalf("source+deliver template should report run-backend and deliver, got %v", caps)
	}
	if !strings.Contains(tpl.Capabilities(), "runs:onepassword-cli") {
		t.Fatalf("capabilities should mention the backend: %s", tpl.Capabilities())
	}
}

func TestParseDiscoveryRule(t *testing.T) {
	doc := `
kind: discovery
name: openai-zshrc
version: 1
provider: env
discover:
  - source: env-lines
    path: ~/.zshrc
    map: {OPENAI_API_KEY: OPENAI_API_KEY}
    risk: high
`
	tpl, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if tpl.Capabilities() != "read-only (discovery)" {
		t.Fatalf("capabilities = %q", tpl.Capabilities())
	}
}

func TestCapabilitiesString(t *testing.T) {
	caps := Get("aws").Capabilities()
	for _, want := range []string{"writes:file", "writes:agent-env", "mints:aws-sts-session-policy"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("capabilities %q missing %q", caps, want)
		}
	}
}
