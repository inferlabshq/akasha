package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// These pin the shape of the SERVER-DERIVED half of a policy request: which
// facts each door establishes, and what the engine is entitled to conclude from
// the ones it did not get.
//
// They exist because that half drifted. Six gates each hand-populated a
// different subset of policy.Request, and the one rule an operator is most
// likely to write — `{provider: aws, effect: deny}` — was enforced on /assume
// (403) and not on /retrieve (200, with the plaintext), because the /retrieve
// gate never resolved a provider and globMatch("aws", "") is false. Every test
// here is a property that must survive any later attempt to unify that
// derivation, not a description of how it is currently spelled.

// A vault-wide operation names no provider, and says so.
//
// "This operation involves no provider" and "nobody looked" are different
// answers, and only the second may fail closed. If the two are conflated in the
// restrictive direction, ONE `{provider: …, effect: deny}` rule silently becomes
// a denial of /label/list and /vault/purge as well — operations that have
// nothing to do with that provider.
func TestProviderRuleDoesNotBlanketVaultWideGates(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - provider: aws
    effect: deny
    reason: aws is off limits
`)
	if code, body := humanGet(t, ts, "/label/list"); code != 200 {
		t.Errorf("/label/list under an aws deny: got %d, want 200 — a provider rule must not "+
			"blanket an operation that names no provider\n%s", code, body)
	}
	if code, body := post(t, ts, "/vault/purge", map[string]string{}, ""); code != 200 {
		t.Errorf("/vault/purge under an aws deny: got %d, want 200 (%v)", code, body)
	}
}

// The other direction, and the one that is easy to lose: declaring "no provider"
// must not let a provider-scoped ALLOW rule grant on these doors either.
//
// This is the surviving hole in the derivation named out loud. Which subject a
// gate declares is a choice, not a compile error: a gate that names a secret but
// declares itself vault-wide would evaluate as resolved-and-empty and slip past
// every provider rule — the original bug, moved rather than fixed. /label/list
// and /vault/purge are the only two doors entitled to that answer.
func TestProviderRuleCannotGrantOnVaultWideGates(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
default: deny
rules:
  - provider: aws
    effect: allow
    reason: aws is fine
`)
	if code, _ := humanGet(t, ts, "/label/list"); code != 403 {
		t.Errorf("/label/list under an aws allow: got %d, want 403 — resolved-and-empty is not "+
			"a match for a named provider, so this rule must not grant here", code)
	}
	if code, _ := post(t, ts, "/vault/purge", map[string]string{}, ""); code != 403 {
		t.Errorf("/vault/purge under an aws allow: got %d, want 403", code)
	}
}

// A secret that answers to NO label is resolved-and-empty too, not unevaluable.
//
// The trap is structural: derive the label set from "every name this token
// answers to" and a token with no names yields an empty slice, the per-name loop
// never runs, "all of them must pass" is vacuously true, and the gate is skipped
// entirely for every unlabelled secret in the vault. Exactly one view has to
// come back.
func TestUnlabelledSecretIsStillGated(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
default: deny
rules: []
`)
	token := storeSSN(t, ts)
	if code, body := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "claude", "requesting_tool": "lookup",
	}, ""); code != 403 {
		t.Fatalf("/retrieve of an unlabelled secret under default:deny: got %d, want 403 — "+
			"a token with no labels must still produce one evaluation, not zero (%v)", code, body)
	}
}

// And the matching half: resolved-and-empty is not a provider match, so the same
// unlabelled secret is untouched by a provider rule.
func TestUnlabelledSecretIsNotMatchedByAProviderRule(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - provider: aws
    effect: deny
    reason: aws is off limits
`)
	token := storeSSN(t, ts)
	code, out := post(t, ts, "/retrieve", map[string]string{
		"token": token, "agent_id": "claude", "requesting_tool": "lookup",
	}, "")
	if code != 200 {
		t.Fatalf("/retrieve of an unlabelled secret under an aws deny: got %d, want 200 — "+
			"one provider rule must not deny every unlabelled secret on the machine (%v)", code, out)
	}
}

// `brokerable` is read from the template of the label BEING EVALUATED, inside
// the per-label loop — not once, from the name the caller happened to ask with.
//
// zz:1 is an alias of a brokerable aws credential. Hoisting the template lookup
// out of the loop would evaluate the whole request as "zz", a provider this
// machine has no template for and therefore not brokerable, and the rule that
// routes agents away from session credentials would stop applying to a secret it
// covers under its other name.
func TestBrokerableIsReadPerLabelNotPerRequestedName(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: assume
    brokerable: true
    effect: deny
    reason: use the per-operation route
`)
	seedAWSCreds(t, vlt) // binds aws:default, which declares a helper route
	tok, err := vlt.GetLabel("aws:default")
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("zz:1", tok); err != nil {
		t.Fatal(err)
	}

	// Control: under its own name the rule bites.
	if code, _ := humanGet(t, ts, "/credential/retrieve?name=aws:default"); code != 403 {
		t.Fatalf("aws:default: got %d, want 403 from the brokerable rule", code)
	}

	// The property: the alias is the same secret, so the aws view is evaluated
	// too and carries aws's brokerability.
	code, body := humanGet(t, ts, "/credential/retrieve?name=zz:1")
	if code != 403 {
		t.Fatalf("alias zz:1: got %d, want 403 — brokerable must be read from each label's own "+
			"template, not once from the requested name\n%s", code, body)
	}
}

// An unknown provider is routine on this path, not an edge case: the alias union
// evaluates whatever names a secret answers to, and `zz:` and `env:` have no
// template on any machine. The template lookup has to tolerate that without
// panicking and without skipping the gate.
func TestAliasWithNoTemplateStillEvaluates(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - provider: aws
    effect: deny
    reason: aws is off limits
`)
	tok := storeSSN(t, ts)
	for _, n := range []string{"aws:prod", "zz:1"} {
		if err := vlt.SetLabel(n, tok); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := humanGet(t, ts, "/credential/retrieve?name=zz:1"); code != 403 {
		t.Fatalf("alias zz:1 of an aws secret: got %d, want 403 (%s)", code, body)
	}
}

// Replacing the policy engine must not quietly drop the derivation with it.
//
// SetPolicyEngine already re-applies the state store, the passphrase verifier
// and the notifier, and its comment names the hazard: a security control that
// disappears as a side effect of swapping an implementation is the kind nobody
// notices. Whatever supplies the server-derived facts is now on that list, and
// this is the test that says so — a second engine, installed after the server is
// already serving, must still evaluate every name a secret answers to.
func TestSwappedPolicyEngineKeepsTheAliasUnion(t *testing.T) {
	dir := t.TempDir()
	ts, vlt, srv := newSwappablePolicyServer(t, "rules: []\n")

	tok := storeSSN(t, ts)
	if err := vlt.SetLabel("aws:prod", tok); err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("zz:1", tok); err != nil {
		t.Fatal(err)
	}

	// A SECOND engine, built from scratch and installed over the first.
	other := storeSSN(t, ts)
	if err := vlt.SetLabel("github:work", other); err != nil {
		t.Fatal(err)
	}

	// A SECOND engine, built from scratch and installed over the first.
	polPath := filepath.Join(dir, "swapped.yaml")
	if err := os.WriteFile(polPath, []byte(`
default: deny
rules:
  - action: assume
    provider: aws
    effect: deny
    reason: production AWS is off limits
  - action: assume
    provider: github
    effect: allow
`), 0600); err != nil {
		t.Fatal(err)
	}
	srv.SetPolicyEngine(policy.NewEngine(polPath))

	if code, _ := humanGet(t, ts, "/credential/retrieve?name=aws:prod"); code != 403 {
		t.Fatalf("aws:prod after the swap: got %d, want 403 — the replacement engine is not enforcing", code)
	}
	code, body := humanGet(t, ts, "/credential/retrieve?name=zz:1")
	if code != 403 {
		t.Fatalf("alias zz:1 after the swap: got %d, want 403 — the replacement engine lost the "+
			"alias union, so the looser name launders the stricter one\n%s", code, body)
	}
	// And the half a lost derivation actually shows up in. An engine with no
	// resolver still DENIES correctly — an unevaluated condition fails closed —
	// so a deny-only test would pass while the control was gone. What breaks is
	// every provider-scoped ALLOW: nothing resolves a provider, so no such rule
	// can ever fire, and the machine locks itself out silently.
	if code, body := humanGet(t, ts, "/credential/retrieve?name=github:work"); code != 200 {
		t.Fatalf("github:work after the swap: got %d, want 200 — the replacement engine cannot "+
			"resolve a provider, so its `provider: github → allow` rule never matches\n%s", code, body)
	}
}

// ─── Route coverage ─────────────────────────────────────────────────────────

// Every route the mux registers either consults the policy engine or is named
// here with a reason.
//
// This is the one check the type system cannot make. A gate can be given the
// wrong subject, and a new endpoint can be written with no gate at all — and
// both compile. So: stand the daemon up under `default: deny`, walk the routes
// registered in server.go, and require a 403 from each. An endpoint that
// legitimately does not ask the policy engine has to be added to
// ungatedRoutes below, which turns a silent omission into a line of code
// someone has to justify in review.
//
// Deriving the route list from the source rather than restating it is the
// point: adding `s.mux.HandleFunc("/new", …)` fails this test until its author
// decides which list it belongs in.
func TestDenyAllPolicyCoversEveryRoute(t *testing.T) {
	// Endpoints that do NOT consult the policy engine, each with the reason it
	// is not a credential-access decision.
	ungatedRoutes := map[string]string{
		"/health": "liveness only; unauthenticated by design and discloses nothing",
		"/wrap":   "redacts secrets INTO the vault; it hands nothing back, so there is no access to gate",
		"/store":  "writes a new secret; the value came from the caller, so policy has nothing to protect yet",
		// The run endpoints are gated by identity rather than by policy: begin
		// and end are human-only, attach requires the run's own key. A policy
		// verb for them would be a second, weaker copy of that check.
		"/run/begin":  "human-only, enforced by identity",
		"/run/attach": "requires the run's own key",
		"/run/end":    "human-only, enforced by identity",
		"/shutdown":   "human-only, enforced by identity",
	}

	// A request per gated route that reaches its policy gate. The bodies are
	// well-formed on purpose: a 400 from a decode failure would pass a
	// "not 200" assertion while proving nothing.
	requests := map[string]struct {
		method, path string
		body         interface{}
	}{
		"/retrieve": {"POST", "/retrieve", map[string]string{
			"token": "tok", "agent_id": "claude", "requesting_tool": "lookup"}},
		"/grant": {"POST", "/grant", map[string]interface{}{
			"token": "tok", "grantor_agent": "a", "grantee_agent": "b", "allowed_tool": "t"}},
		"/inspect":             {"GET", "/inspect?token=tok", nil},
		"/identity":            {"GET", "/identity?provider=aws&profile=default", nil},
		"/label/set":           {"POST", "/label/set", map[string]string{"name": "a:b", "token": "tok"}},
		"/credential/retrieve": {"GET", "/credential/retrieve?name=a:b", nil},
		"/label/list":          {"GET", "/label/list", nil},
		"/label/delete":        {"POST", "/label/delete", map[string]string{"name": "a:b"}},
		"/profile/save": {"POST", "/profile/save", map[string]interface{}{
			"provider": "aws", "profile": "default", "token": "tok"}},
		"/vault/purge": {"POST", "/vault/purge", map[string]string{}},
		"/put": {"POST", "/put", map[string]interface{}{
			"label": "env:x", "fields": map[string]string{"k": "v"}}},
		"/assume":  {"POST", "/assume", map[string]string{"provider": "aws", "profile": "default"}},
		"/resolve": {"GET", "/resolve?provider=aws&instance=default", nil},
	}

	ts, vlt, _ := newPolicyTestServer(t, "default: deny\nrules: []\n")
	trustBundle(t)
	seedAWSCreds(t, vlt)

	for _, route := range registeredRoutes(t) {
		if why, ok := ungatedRoutes[route]; ok {
			if why == "" {
				t.Errorf("%s is listed as ungated with no reason", route)
			}
			continue
		}
		rq, ok := requests[route]
		if !ok {
			t.Errorf("route %s is registered but this test does not exercise it: either add a "+
				"request for it (and expect 403 under default:deny), or add it to ungatedRoutes "+
				"with the reason it does not consult the policy engine", route)
			continue
		}
		var code int
		var body string
		if rq.method == "GET" {
			code, body = humanGet(t, ts, rq.path)
		} else {
			body = postRaw(t, ts, rq.path, rq.body, "")
			code, _ = post(t, ts, rq.path, rq.body, "")
		}
		if code != http.StatusForbidden {
			t.Errorf("%s under `default: deny`: got %d, want 403 — this endpoint does not reach "+
				"the policy gate\n%s", route, code, strings.TrimSpace(body))
		}
	}
}

// registeredRoutes reads the mux registrations out of server.go. http.ServeMux
// cannot be asked what it holds, and a hand-maintained copy of the list would
// go stale in exactly the case this test is for.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	re := regexp.MustCompile(`s\.mux\.HandleFunc\("([^"]+)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("found no mux registrations in server.go — this test's source scan has rotted, " +
			"which would silently make it assert nothing")
	}
	sort.Strings(out)
	return out
}

// newSwappablePolicyServer is newPolicyTestServer, but it also hands back the
// *server.Server — so a test can install a SECOND policy engine after the
// daemon is already serving, which is the case SetPolicyEngine's own comment is
// about.
func newSwappablePolicyServer(t *testing.T, policyYAML string) (*httptest.Server, *vault.Vault, *server.Server) {
	t.Helper()
	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(polPath, []byte(policyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(polPath)
	eng.SetApprover(&stubApprover{})

	srv := server.New(classifier.New(nil), vlt, auditL)
	srv.SetPolicyEngine(eng)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); auditL.Close(); vlt.Close() })
	return humanServer(t, ts, vlt), vlt, srv
}

// A denial has to say which of the secret's names refused, and be logged
// against that name's own classification.
//
// The fan-out over a token's labels lives inside the engine now, so the gate no
// longer holds the per-name request it used to read these off. policy.Denial is
// what carries them back, and this is the test that makes it load-bearing rather
// than decorative: without it a caller who asked for zz:1 is told "denied by
// policy: production AWS is off limits" with no way to connect the two, and the
// DENIED audit event records an empty token, category and risk.
func TestAliasDenialNamesTheOtherLabelAndIsAuditedAgainstIt(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, `
rules:
  - action: assume
    provider: aws
    effect: deny
    reason: production AWS is off limits
`)
	tok := storeSSN(t, ts)
	for _, n := range []string{"aws:prod", "zz:1"} {
		if err := vlt.SetLabel(n, tok); err != nil {
			t.Fatal(err)
		}
	}

	code, body := humanGet(t, ts, "/credential/retrieve?name=zz:1")
	if code != 403 {
		t.Fatalf("alias read: got %d, want 403", code)
	}
	if !strings.Contains(body, "aws:prod") {
		t.Errorf("a denial on a name the caller never typed must name the label whose rules "+
			"applied; got:\n%s", body)
	}

	for _, e := range waitForAudit(t, dir, "DENIED", 1) {
		if e["action"] != "DENIED" {
			continue
		}
		// Tokens are digested on the way into the log, so the assertion is that
		// one is PRESENT: losing the failing view would leave this blank.
		if got, _ := e["token"].(string); got == "" {
			t.Error("DENIED event carries no token — the event must describe the view that refused")
		}
		if e["risk"] != "critical" || e["category"] != "Credential" {
			t.Errorf("DENIED category/risk = %v/%v, want Credential/critical", e["category"], e["risk"])
		}
		return
	}
	t.Fatal("no DENIED event for the refused alias read")
}

// The same, for the gates that go through authorize() rather than the credential
// wrapper — where the DENIED event has no other source for these fields.
//
// authorizeCredentialAccess writes its own event from constants it already
// holds, so it would pass this test whatever the engine returned. /retrieve does
// not: the entry's own classification reaches the log only by travelling back on
// the Denial.
func TestDeniedEventOnTheTokenPathDescribesTheViewThatRefused(t *testing.T) {
	ts, vlt, dir := newPolicyTestServerDir(t, `
rules:
  - provider: aws
    effect: deny
    reason: aws is off limits
`)
	tok := storeSSN(t, ts) // stored as SSN / critical
	if err := vlt.SetLabel("aws:prod", tok); err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, ts, "/retrieve", map[string]string{
		"token": tok, "agent_id": "claude", "requesting_tool": "lookup",
	}, ""); code != 403 {
		t.Fatalf("retrieve of an aws-labelled secret: got %d, want 403", code)
	}

	for _, e := range waitForAudit(t, dir, "DENIED", 1) {
		if e["action"] != "DENIED" {
			continue
		}
		if e["category"] != "SSN" || e["risk"] != "critical" {
			t.Errorf("DENIED category/risk = %v/%v, want SSN/critical — the refusing view's "+
				"classification is what makes this record filterable", e["category"], e["risk"])
		}
		if got, _ := e["token"].(string); got == "" {
			t.Error("DENIED event carries no token")
		}
		return
	}
	t.Fatal("no DENIED event")
}

// Removing a label is rated critical, with no routine case.
//
// DELETE plus CREATE is a re-point spelled in two commands, so a `min_risk:
// critical` bind rule has to cover the delete half or it covers nothing:
// `akasha label rm github:default` followed by `akasha put github:default` moves
// the name onto a credential of the caller's choosing without ever tripping a
// rule written against the re-point.
func TestUnbindIsRatedCritical(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
rules:
  - action: bind
    min_risk: critical
    effect: deny
    reason: detaching a name needs review
`)
	tok, err := vlt.Store("x", "Credential", "high", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("aws:default", tok); err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, ts, "/label/delete", map[string]string{"name": "aws:default"}, ""); code != 403 {
		t.Fatalf("delete under a min_risk:critical bind rule: got %d, want 403", code)
	}
	if _, err := vlt.GetLabel("aws:default"); err != nil {
		t.Fatalf("the denied delete removed the label anyway: %v", err)
	}
}

// The entry's classification reaches EVERY token-addressed gate, not just the
// one that returns plaintext.
//
// /inspect's own comment records the bug: the gate ran with category and risk
// empty, so `min_risk` could never match an inspect and "deny metadata about
// critical secrets" silently did nothing. Nothing guarded it, and the
// derivation has since moved — so this asserts the property directly, on both
// gates that only ever had it by hand.
func TestMinRiskReachesEveryTokenAddressedGate(t *testing.T) {
	ts, _, _ := newPolicyTestServer(t, `
rules:
  - min_risk: critical
    effect: deny
    reason: critical secrets are not discussed
`)
	tok := storeSSN(t, ts) // SSN / critical

	if code, body := humanGet(t, ts, "/inspect?token="+tok); code != 403 {
		t.Errorf("/inspect of a critical secret: got %d, want 403 — a min_risk rule must reach "+
			"the metadata door, or `deny anything critical` covers everything except the "+
			"endpoint that describes it\n%s", code, body)
	}
	if code, body := post(t, ts, "/grant", map[string]interface{}{
		"token": tok, "grantor_agent": "a", "grantee_agent": "b", "allowed_tool": "t",
	}, ""); code != 403 {
		t.Errorf("/grant of a critical secret: got %d, want 403 (%v)", code, body)
	}

	// And a medium-risk entry is untouched by the same rule, so this is a
	// classification reaching the gate rather than a blanket denial.
	_, st := post(t, ts, "/store", map[string]string{
		"agent_id": "seeder", "tool_name": "seed", "content": "someone@example.com",
		"category": "Email", "risk": "medium",
	}, "")
	if code, body := humanGet(t, ts, "/inspect?token="+st["token"].(string)); code != 200 {
		t.Errorf("/inspect of a medium-risk secret: got %d, want 200\n%s", code, body)
	}
}

// Both halves of a label are resolved AND declared resolved.
//
// The bits are separate on purpose, so the derivation can set one without the
// other — which means it can also forget one. Forgetting the instance bit fails
// closed and is therefore silent: deny rules keep working, the machine keeps
// refusing, and only `instance:`-scoped ALLOW rules quietly stop matching. This
// is the test that notices.
func TestInstanceScopedAllowActuallyFires(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: deny
rules:
  - action: assume
    provider: aws
    instance: prod
    effect: allow
`)
	tok := storeSSN(t, ts)
	if err := vlt.SetLabel("aws:prod", tok); err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("aws:dev", secondSecret(t, vlt)); err != nil {
		t.Fatal(err)
	}

	if code, body := humanGet(t, ts, "/credential/retrieve?name=aws:prod"); code != 200 {
		t.Errorf("aws:prod under a provider+instance allow: got %d, want 200 — if the instance "+
			"was resolved but not DECLARED resolved, this rule can never match\n%s", code, body)
	}
	// The instance half is doing work: a sibling profile is not covered.
	if code, _ := humanGet(t, ts, "/credential/retrieve?name=aws:dev"); code != 403 {
		t.Errorf("aws:dev under an instance:prod allow: got %d, want 403", code)
	}
}

// secondSecret vaults another secret, so a test can tell one label from another.
func secondSecret(t *testing.T, vlt *vault.Vault) string {
	t.Helper()
	tok, err := vlt.Store("second", "Credential", "critical", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A gate must derive from what it ACTUALLY touches, and nothing else catches it
// when it does not.
//
// Unexporting the fact fields made hand-population a compile error, which
// retired the original bug: a gate can no longer supply a value without also
// declaring it resolved. It did NOT retire the shape. A gate still chooses its
// SUBJECT, and choosing the wrong one is a full policy bypass — measured, on a
// route added the way a new gate's author would add it:
//
//	correct   /credential/retrieve?name=aws:prod -> 403 denied by policy
//	wrong     /zzprobe?name=aws:prod             -> 200 {"token":"vault://…"}
//
// `go build` passed and the entire server suite stayed green, including
// TestDenyAllPolicyCoversEveryRoute — because that test drives every route under
// bare `default: deny`, where a subject resolving to NOTHING still 403s. It
// proves the gate was called. It cannot prove it was called with a real subject.
//
// This test is the missing half. Every gated route is driven against a REAL
// labelled credential under a rule that only matches a resolved provider, so a
// route that declares itself vault-wide over something that names a provider
// answers 200 where its neighbours answer 403.
//
// `?*` and not `*`, and the difference is the whole mechanism: globMatch("*", "")
// is TRUE, so `*` matches a vault-wide gate too and would prove nothing. `?*`
// requires at least one character, so it matches "aws" and not "".
func TestGatesDeriveFromWhatTheyActuallyTouch(t *testing.T) {
	// Routes that genuinely name no provider. Being on this list is a claim
	// about the endpoint, and it has to be true: these sweep or list the whole
	// vault, so scoping them to one provider would be wrong rather than safe.
	vaultWide := map[string]string{
		"/label/list":  "lists every label there is; a provider scope would be a lie about what it touched",
		"/vault/purge": "sweeps orphaned entries across the whole vault, not one provider's",
	}

	// Carried from TestDenyAllPolicyCoversEveryRoute. Kept as its own copy on
	// purpose: these two tests ask different questions, and sharing the list
	// would let an endpoint become ungated in one sense while silently
	// inheriting the other's justification.
	ungated := map[string]bool{
		"/health": true, "/wrap": true, "/store": true,
		"/run/begin": true, "/run/attach": true, "/run/end": true, "/shutdown": true,
	}

	ts, vlt, _ := newPolicyTestServer(t, "default: allow\nrules:\n  - provider: \"?*\"\n    effect: deny\n    reason: anything that resolved a provider\n")
	trustBundle(t)
	seedAWSCreds(t, vlt)

	tok, err := vlt.GetLabel("aws:default")
	if err != nil {
		t.Fatalf("seeded label should resolve: %v", err)
	}

	// Every request addresses the SAME real credential, so a correct gate always
	// has a provider to resolve. A placeholder token would resolve to nothing and
	// make every route look vault-wide — passing this test for the wrong reason.
	requests := map[string]struct {
		method, path string
		body         interface{}
	}{
		"/retrieve": {"POST", "/retrieve", map[string]string{
			"token": tok, "agent_id": "claude", "requesting_tool": "lookup"}},
		"/grant": {"POST", "/grant", map[string]interface{}{
			"token": tok, "grantor_agent": "a", "grantee_agent": "b", "allowed_tool": "t"}},
		"/inspect":             {"GET", "/inspect?token=" + tok, nil},
		"/identity":            {"GET", "/identity?provider=aws&profile=default", nil},
		"/label/set":           {"POST", "/label/set", map[string]string{"name": "aws:default", "token": tok}},
		"/credential/retrieve": {"GET", "/credential/retrieve?name=aws:default", nil},
		"/label/delete":        {"POST", "/label/delete", map[string]string{"name": "aws:default"}},
		"/profile/save": {"POST", "/profile/save", map[string]interface{}{
			"provider": "aws", "profile": "default", "token": tok}},
		"/put": {"POST", "/put", map[string]interface{}{
			"label": "aws:default", "fields": map[string]string{"k": "v"}}},
		"/assume":  {"POST", "/assume", map[string]string{"provider": "aws", "profile": "default"}},
		"/resolve": {"GET", "/resolve?provider=aws&instance=default", nil},
	}

	for _, route := range registeredRoutes(t) {
		if ungated[route] {
			continue
		}
		if why, ok := vaultWide[route]; ok {
			if why == "" {
				t.Errorf("%s claims to be vault-wide with no reason", route)
			}
			continue
		}
		rq, ok := requests[route]
		if !ok {
			t.Errorf("route %s is gated but this test does not address it at a real credential: add a "+
				"request that names aws:default (and expect 403), or add it to vaultWide with the "+
				"reason it genuinely names no provider", route)
			continue
		}

		var code int
		var body string
		if rq.method == "GET" {
			code, body = humanGet(t, ts, rq.path)
		} else {
			body = postRaw(t, ts, rq.path, rq.body, "")
			code, _ = post(t, ts, rq.path, rq.body, "")
		}
		if code != http.StatusForbidden {
			t.Errorf("%s acts on aws:default but was NOT denied by `{provider: \"?*\"}`: got %d.\n"+
				"Its gate resolved no provider, which means it declares a subject that does not "+
				"describe what it touches — a rule an operator writes about aws does not reach it.\n%s",
				route, code, strings.TrimSpace(body))
		}
	}
}
