package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// The two ways the daemon can fail to establish what a subject IS are
// deliberately DIFFERENT, and they are only reachable when the vault itself is
// unreadable — which the auth middleware turns into a 5xx long before any
// handler runs. So these are white-box: they call the derivation directly, on a
// server whose vault has been closed underneath it.

// unreadableServer returns a server whose vault answers every query with an
// error, plus a token that was real before the lights went out.
func unreadableServer(t *testing.T) (*Server, string) {
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
	t.Cleanup(func() { auditL.Close() })
	tok, err := vlt.Store("secret", "Credential", "critical", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlt.SetLabel("aws:prod", tok); err != nil {
		t.Fatal(err)
	}
	s := New(classifier.New(nil), vlt, auditL)
	// Point the engine at a path that does not exist: a missing policy file is
	// the permissive default, so anything these tests observe comes from the
	// derivation and not from a rule.
	s.SetPolicyEngine(policy.NewEngine(filepath.Join(dir, "policy.yaml")))
	vlt.Close()
	return s, tok
}

// The CREDENTIAL path fails HARD when it cannot enumerate a token's aliases.
//
// Every label a secret answers to has to pass, so being unable to list them is
// being unable to claim the rules were applied. This is the door that hands back
// a working credential, and "we could not check" must not resolve to "go ahead"
// — under the out-of-the-box configuration (no policy file, default allow) a
// soft failure here would be a 200.
func TestAliasEnumerationFailureDeniesOnTheCredentialPath(t *testing.T) {
	s, tok := unreadableServer(t)
	c := caller{agentID: "akasha-assume", agentSrc: policy.ServerAssigned,
		tool: "akasha_assume", toolSrc: policy.ServerAssigned}

	err := s.authorizeCredentialNames(context.Background(), "assume", "aws:prod", tok, c)
	if err == nil {
		t.Fatal("an unreadable vault must refuse the credential gate outright: the aliases could " +
			"not be enumerated, so the rules were not applied to every name this secret answers to")
	}
	if !strings.Contains(err.Error(), "cannot determine which credentials this token is bound to") {
		t.Errorf("the refusal must name the vault as the thing that failed, not imply a policy "+
			"decision nobody made: %v", err)
	}
}

// The TOKEN path fails SOFTLY, and that difference is deliberate.
//
// /retrieve, /grant and /inspect return the ORIGINAL request with the fact set
// left UNSET, which is unevaluable rather than resolved: restrictive rules still
// bind, permissive ones cannot. Marking the facts established here — the easy
// slip, since the labelled copy is the variable in scope — would claim the
// provider was resolved to "" on the one path where nothing was resolved at all,
// and a `{provider: "*", effect: allow}` rule would then grant on a vault the
// daemon cannot read.
func TestTokenLookupFailureLeavesTheFactsUnestablished(t *testing.T) {
	s, tok := unreadableServer(t)

	views, err := serverFacts{s}.FactsFor(policy.OfToken(tok))
	if err != nil {
		t.Fatalf("the token path fails softly, not with an error: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("an unreadable vault must still yield exactly one evaluation, got %d — zero would "+
			"make `every view must pass` vacuously true and skip the gate", len(views))
	}
	if views[0].Known() != 0 {
		t.Errorf("Known = %d, want 0: a vault we cannot read must not widen what policy allows, "+
			"so no server-derived fact may be marked established here", views[0].Known())
	}
}

// A gate that does not say what it acts on is refused, not read as vault-wide.
//
// The zero SubjectKind could have been the vault-wide one — every current gate
// that means "no provider" would still work — and that is exactly why it is not.
// Vault-wide is resolved-and-EMPTY, which a provider rule does not match, so
// forgetting would have bought the permissive reading. Here forgetting costs a
// refusal.
func TestUnnamedSubjectIsRefused(t *testing.T) {
	s, _ := unreadableServer(t)
	if _, err := (serverFacts{s}).FactsFor(policy.Subject{}); err == nil {
		t.Fatal("a subject nobody named must be refused: the alternative is that a new gate which " +
			"forgets to name one silently evaluates as `this operation names no provider`")
	}
}

// A vault-wide gate declares that it LOOKED. Both facts are marked resolved, and
// both come back empty — which is what keeps a provider rule from matching in
// either direction.
func TestVaultWideDeclaresResolvedAndEmpty(t *testing.T) {
	s, _ := unreadableServer(t)
	views, err := serverFacts{s}.FactsFor(policy.VaultWide("Credential", "critical"))
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("want exactly one view, got %d", len(views))
	}
	if !views[0].Known().Has(policy.FactProvider | policy.FactInstance) {
		t.Error("a vault-wide gate must declare that it resolved the provider dimension, or a " +
			"provider-scoped ALLOW rule could grant on it")
	}
	if views[0].Provider() != "" || views[0].Instance() != "" {
		t.Errorf("a vault-wide gate names no provider, got %q:%q", views[0].Provider(), views[0].Instance())
	}
}

// A vault the daemon cannot read is a SERVER fault on the bind path, not a
// refusal — and the two gate wrappers say so differently on purpose.
//
// The credential path reports the same failure to the caller as a 403 naming the
// vault; the bind path reports a 500 naming `akasha status`, because a write the
// daemon could not evaluate is not a decision anyone made. Both fail closed;
// only the wording and the status differ, and both are the behaviour that was
// there before the derivation was unified.
func TestBindGateReportsAnUnreadableVaultAsAServerFault(t *testing.T) {
	s, tok := unreadableServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/label/set", nil)

	if s.authorizeBind(w, r, "aws:prod", tok, "") {
		t.Fatal("a bind must not be authorized when the daemon cannot enumerate the target " +
			"token's other names — every one of them has to pass")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: the rules were never applied, so this is not a policy "+
			"denial and must not be reported as one", w.Code)
	}
	if !strings.Contains(w.Body.String(), "akasha status") {
		t.Errorf("the refusal should name the vault as the thing to check: %q", w.Body.String())
	}
}
