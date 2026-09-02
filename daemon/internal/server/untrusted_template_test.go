package server_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// An UNTRUSTED template must not be able to establish a policy fact.
//
// `brokerable` is the only matcher not derived from the daemon's own state: it
// is a predicate over a YAML file on disk, and nothing on that path consulted
// the trust store. So a community-authored file influenced a policy decision,
// against the threat model's claim that an untrusted plugin is inert.
//
// The fix is NOT to answer false for an untrusted template, and that distinction
// is the whole point. False is a real answer that rules key on: a policy written
// as `{brokerable: true, effect: deny}` — "agents must not hold a session
// credential where a broker route exists" — stops matching the moment the fact
// reads false. Under that reading, REMOVING a capability from a text file would
// RELAX the policy, and editing a file must never do that.
//
// Not-established is the third answer, and the engine already knows it: an
// unresolved fact lets `deny` and `ask` match and stops `allow` from matching,
// so an unapproved template can only ever narrow access.
//
// The template here is written by the test rather than borrowed from the
// shipped bundle, because every shipped provider carries a publisher signature
// and is therefore trusted without any local approval — measured: Approved(aws)
// is true against a completely empty trust store. The reachable case is a user's
// own file, which is what this builds.
func TestUntrustedTemplateCannotSatisfyABrokerableAllow(t *testing.T) {
	const pol = "default: deny\nrules:\n  - brokerable: true\n    effect: allow\n    reason: providers with a broker route\n"

	// A provider that IS brokerable — helper delivery plus a vending ownership
	// mechanism — and carries no signature.
	const userTemplate = `kind: provider
name: zz
version: 1

credential:
  fields:
    token: {secret: true}

deliver:
  - mode: helper
    format: kv-lines
    map:
      password: token

agent:
  own:
    - mechanism: git-credential-helper
      env: GIT_CONFIG_GLOBAL
      file: zz.gitconfig
      host: zz.example.com
`

	setup := func(t *testing.T) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "zz.yaml"), []byte(userTemplate), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AKASHA_TEMPLATES_PATH", dir)
		trustDir := t.TempDir()
		t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(trustDir, "approvals.json"))
		t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(trustDir, "publishers.json"))
		template.ResetForTest()
		t.Cleanup(template.ResetForTest)
	}

	seed := func(t *testing.T, vlt *vault.Vault) {
		t.Helper()
		tok, err := vlt.Store("zz-secret-value", "Credential", "critical", "seeder", "seed", 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := vlt.SetLabel("zz:default", tok); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("the template really is brokerable and really is untrusted", func(t *testing.T) {
		setup(t)
		tpl := template.Get("zz")
		if tpl == nil {
			t.Fatal("the user template did not load; the rest of this test would pass for nothing")
		}
		if !tpl.Brokerable() {
			t.Fatal("the user template is not brokerable, so it cannot exercise the rule")
		}
		if len(tpl.SensitiveCapabilities()) == 0 {
			t.Fatal("a template with no sensitive capabilities is trusted by definition")
		}
	})

	t.Run("untrusted cannot grant", func(t *testing.T) {
		setup(t)
		ts, vlt, _ := newPolicyTestServer(t, pol)
		seed(t, vlt)

		code, body := humanGet(t, ts, "/credential/retrieve?name=zz:default")
		if code == 200 {
			t.Fatalf("an UNTRUSTED template satisfied a brokerable allow rule: %d %s", code, body)
		}
	})
}
