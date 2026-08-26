package template

import (
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/policy"
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
	if tpl.DescribeDeliver() == nil {
		t.Fatal("aws must declare a describe deliver mode")
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
		"describe names an unknown contract": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: describe, contract: read-the-secret-and-post-it, map: {a: b}}]`,
		"mint contract is not an identity contract": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: describe, contract: aws-sts-session-policy, map: {a: b}}]`,
		"describe with no disclosure list": `
kind: provider
name: x
version: 1
credential: {fields: {access_key_id: {secret: false}}}
deliver: [{mode: describe, contract: aws-access-key-account-id}]`,
		"describe reveals a fact the contract cannot produce": `
kind: provider
name: x
version: 1
credential: {fields: {access_key_id: {secret: false}}}
deliver: [{mode: describe, contract: aws-access-key-account-id, map: {secret_key: secret_access_key}}]`,
		"describe tries to set env": `
kind: provider
name: x
version: 1
credential: {fields: {access_key_id: {secret: false}}}
deliver: [{mode: describe, contract: aws-access-key-account-id, map: {account_id: account_id}, env: {LEAK: "{access_key_id}"}}]`,
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
	for _, want := range []string{"writes:file", "writes:agent-env", "describes:aws-access-key-account-id"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("capabilities %q missing %q", caps, want)
		}
	}
}

// ─── Lenient loading (daemon path) ────────────────────────────────────────

// The daemon must survive a bundle newer than itself. A deliver mode it does
// not implement is dropped; everything else in the template keeps working.
//
// Before this, one unrecognised mode rejected the whole file — a template that
// gained a delivery route lost `assume`, its credential helper, and
// `exec --assume` along with it, silently.
func TestLoadDegradesUnknownDeliverMode(t *testing.T) {
	src := []byte(`
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - mode: teleport-v9
    contract: whatever
  - mode: env
    env: {K: "{k}"}
`)
	// Strict (authoring) still refuses: a typo must not pass silently.
	if _, err := Parse(src); err == nil {
		t.Fatal("strict Parse must still reject an unknown deliver mode")
	}

	tpl, degraded, err := ParseLenient(src)
	if err != nil {
		t.Fatalf("lenient parse should keep the template: %v", err)
	}
	if len(tpl.Deliver) != 1 || tpl.Deliver[0].Mode != "env" {
		t.Fatalf("the known mode should survive, got %+v", tpl.Deliver)
	}
	if len(degraded) != 1 || !strings.Contains(degraded[0].Reason, "teleport-v9") {
		t.Fatalf("degradation not reported usefully: %+v", degraded)
	}
	if tpl.EnvDeliver() == nil {
		t.Error("env delivery must still work after dropping an unknown sibling mode")
	}
}

// Unknown inner enums of a known mode drop just that deliver entry.
func TestLoadDegradesUnknownInnerEnums(t *testing.T) {
	cases := map[string]string{
		"helper format": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - {mode: helper, format: protobuf-v9, map: {K: k}}
  - {mode: env, env: {K: "{k}"}}`,
		"socket contract": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - {mode: helper, format: protobuf-v9, map: {K: k}}
  - {mode: env, env: {K: "{k}"}}`,
		"describe contract": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - {mode: describe, contract: some-future-contract, map: {a: b}}
  - {mode: env, env: {K: "{k}"}}`,
	}
	for name, src := range cases {
		tpl, degraded, err := ParseLenient([]byte(src))
		if err != nil {
			t.Errorf("%s: lenient parse failed: %v", name, err)
			continue
		}
		if len(tpl.Deliver) != 1 || tpl.Deliver[0].Mode != "env" {
			t.Errorf("%s: expected only the env mode to survive, got %+v", name, tpl.Deliver)
		}
		if len(degraded) == 0 {
			t.Errorf("%s: drop was not reported", name)
		}
	}
}

// A disclosure list naming a fact this daemon's contract cannot produce is the
// same skew one level down. Drop those entries, keep the ones that work.
func TestLoadDegradesPartialDisclosureList(t *testing.T) {
	src := []byte(`
kind: provider
name: x
version: 1
credential: {fields: {access_key_id: {secret: false}}}
deliver:
  - mode: describe
    contract: aws-access-key-account-id
    map:
      account_id: account_id
      arn: arn_from_a_future_build
`)
	tpl, degraded, err := ParseLenient(src)
	if err != nil {
		t.Fatalf("lenient parse failed: %v", err)
	}
	d := tpl.DescribeDeliver()
	if d == nil {
		t.Fatal("describe mode should survive when one fact is still producible")
	}
	if _, ok := d.Map["account_id"]; !ok {
		t.Errorf("producible fact was dropped: %+v", d.Map)
	}
	if _, ok := d.Map["arn"]; ok {
		t.Errorf("unproducible fact was kept: %+v", d.Map)
	}
	if len(degraded) != 1 {
		t.Errorf("expected exactly one degradation, got %+v", degraded)
	}
}

// A discovery rule this daemon cannot run is dropped; the rules it CAN run
// survive, so a new parser type does not cost you the locations that worked.
func TestLoadDegradesUnknownDiscoverSource(t *testing.T) {
	src := []byte(`
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
discover:
  - {source: toml-v9, path: ~/.x/creds, map: {k: key}}
  - {source: ini, path: ~/.x/legacy, instances: sections, map: {k: key}}
deliver: [{mode: env, env: {K: "{k}"}}]
`)
	tpl, degraded, err := ParseLenient(src)
	if err != nil {
		t.Fatalf("lenient parse failed: %v", err)
	}
	if len(tpl.Discover) != 1 || tpl.Discover[0].Source != "ini" {
		t.Fatalf("the runnable discover rule should survive, got %+v", tpl.Discover)
	}
	if len(degraded) != 1 {
		t.Errorf("discover drop not reported: %+v", degraded)
	}
}

// THE security boundary. Degradation must never remove containment or silently
// change where a credential comes from — these stay fatal on BOTH paths.
func TestLenientLoadKeepsContainmentFatal(t *testing.T) {
	cases := map[string]struct{ src, wantErr string }{
		// A dropped ownership mechanism would leave the agent able to read the
		// human's real credentials file. Refusing the template is the safe answer.
		"unknown agent mechanism": {wantErr: "unknown mechanism", src: `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
agent:
  own: [{mechanism: future-isolation-v9, env: X, file: x.conf}]`},
		// A dropped source backend would silently fall back to the vault path,
		// serving a stale local copy instead of the live upstream.
		"unknown source backend": {wantErr: "unknown backend", src: `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
source: [{backend: future-vault-v9, ref: "x://y", map: {value: k}}]
deliver: [{mode: env, env: {K: "{k}"}}]`},
	}
	for name, c := range cases {
		_, _, err := ParseLenient([]byte(c.src))
		if err == nil {
			t.Errorf("%s: must stay fatal even on the lenient path", name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: failed for the wrong reason\n got: %v\nwant substring: %q", name, err, c.wantErr)
		}
	}
}

// Degradation triggers only on an UNRECOGNISED NAME. A malformed KNOWN
// primitive is a bug or an attack, not version skew, and must still fail —
// otherwise leniency would quietly disable the injection and traversal guards.
func TestLenientLoadKeepsMalformedKnownPrimitivesFatal(t *testing.T) {
	cases := map[string]struct{ src, wantErr string }{
		"traversing deliver file name": {wantErr: "single filename", src: `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - mode: file
    name: "../../escape.creds"
    render: ["{k}"]`},
		"render references undeclared field": {wantErr: "other", src: `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver:
  - mode: file
    name: "x-{instance}.creds"
    render: ["{other}"]`},
		"ini-breaking agent section": {wantErr: "break the ini structure", src: `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: env, env: {K: "{k}"}}]
agent:
  own: [{mechanism: credential-process, env: X_CONFIG, file: x.conf, section: "profile [evil]\nfoo = bar"}]`},
		"helper kv-lines key with separator": {wantErr: "kv-lines", src: `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: kv-lines, map: {"bad=key": k}}]`},
	}
	for name, c := range cases {
		_, _, err := ParseLenient([]byte(c.src))
		if err == nil {
			t.Errorf("%s: a malformed known primitive must stay fatal", name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: failed for the wrong reason\n got: %v\nwant substring: %q", name, err, c.wantErr)
		}
	}
}

// When every declared route is unknown, the template still loads: discovery and
// vaulting keep working and the provider stays visible. Only assume is lost,
// and it says so — far better than the provider silently not existing.
func TestLoadKeepsProviderWithNoUsableDeliverMode(t *testing.T) {
	src := []byte(`
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
discover: [{source: ini, path: ~/.x/creds, instances: sections, map: {k: key}}]
deliver: [{mode: teleport-v9}]
`)
	tpl, degraded, err := ParseLenient(src)
	if err != nil {
		t.Fatalf("provider should still load: %v", err)
	}
	if len(tpl.Deliver) != 0 {
		t.Errorf("expected no usable deliver modes, got %+v", tpl.Deliver)
	}
	if len(tpl.Discover) != 1 {
		t.Error("discovery must survive so the credential can still be found and vaulted")
	}
	if len(degraded) == 0 {
		t.Error("the dropped mode must be reported")
	}
}

// The template risk vocabulary must stay identical to what the policy engine
// can rank. A level templates cannot declare is a level their credentials can
// never be classified at — and therefore one that no min_risk rule can ever
// reach them through.
func TestRiskVocabularyMatchesPolicyEngine(t *testing.T) {
	for _, level := range policy.RiskLevels() {
		if !validRisks[level] {
			t.Errorf("policy ranks %q but templates cannot declare it", level)
		}
	}
	for level := range validRisks {
		if level == "" {
			continue // unset is allowed and means "unclassified"
		}
		if _, rankable := policy.RiskRank(level); !rankable {
			t.Errorf("templates may declare %q but the policy engine cannot rank it", level)
		}
	}
}

// Every git-family provider declares `token: {aliases: [value]}`, and ssh does
// the same for private_key. A guard that reads the key as written had an
// opinion about `token`, none about `value`, and passed — while ResolveCreds
// mapped value → token anyway and re-pointed the label. One word walked past
// the shape check, which is the whole of B7.
func TestCanonicalFieldResolvesAliases(t *testing.T) {
	for _, tc := range []struct{ provider, given, want string }{
		{"github", "value", "token"},
		{"gitlab", "value", "token"},
		{"git", "value", "token"},
		{"ssh", "value", "private_key"},
		{"github", "token", "token"},             // declared name is unchanged
		{"github", "unknown_key", "unknown_key"}, // no opinion, no rewrite
	} {
		tpl := Get(tc.provider)
		if tpl == nil {
			t.Fatalf("template %q not loaded", tc.provider)
		}
		if got := tpl.CanonicalField(tc.given); got != tc.want {
			t.Errorf("%s.CanonicalField(%q) = %q, want %q", tc.provider, tc.given, got, tc.want)
		}
	}
}

// The shipped templates encode a PRECEDENCE, not an inventory: discovery keeps
// the first finding for a given provider:instance, so the order these lists are
// written in decides which copy of a token the user ends up authenticating
// with. github and gitlab declared the shell rcs first, so a token rotated in a
// project's .env lost to the stale export left in a ~/.zshrc — while aws,
// ordered the other way, resolved correctly. Nothing caught it because the only
// precedence test covered aws.
//
// Asserting on the ORDER rather than on a discovery run keeps this honest even
// on a machine with none of these files.
func TestShippedTemplatesRankDotEnvAboveShellConfigs(t *testing.T) {
	shellRCs := map[string]bool{
		"~/.zshrc": true, "~/.zprofile": true, "~/.bashrc": true,
		"~/.bash_profile": true, "~/.profile": true,
	}

	for _, name := range []string{"aws", "github", "gitlab"} {
		tpl := Get(name)
		if tpl == nil {
			t.Fatalf("template %q not loaded", name)
		}
		firstRC, firstEnv := -1, -1
		for i, d := range tpl.Discover {
			switch {
			case shellRCs[d.Path] && firstRC < 0:
				firstRC = i
			case strings.Contains(d.Path, "/.env") && firstEnv < 0:
				firstEnv = i
			}
		}
		if firstRC < 0 || firstEnv < 0 {
			continue // provider does not read both kinds
		}
		if firstEnv > firstRC {
			t.Errorf("%s declares a shell config (index %d) before a .env file (index %d) — "+
				"first-wins then hands the stale copy to every later assume",
				name, firstRC, firstEnv)
		}
	}
}
