package server_test

import (
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// awsKeyFor builds an access key id carrying a known account number, so tests
// assert against a value they chose rather than a captured fixture.
func awsKeyFor(account uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], account<<7)
	raw := make([]byte, 10)
	copy(raw, buf[2:])
	copy(raw[6:], []byte("ABCD"))
	return "AKIA" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

const testAccount = 716969406655

const secretKeyValue = "wJalrXUtnFEMI-THE-SECRET-HALF-K7MDENG"

// seedAWS vaults a full AWS credential chain under aws:<profile> and returns
// the vault token of the secret access key, so tests can assert on whether it
// was ever decrypted.
func seedAWS(t *testing.T, vlt *vault.Vault, profile string, account uint64) (secretTok string) {
	t.Helper()
	akTok, _ := vlt.Store(awsKeyFor(account), "AWSAccessKeyID", "critical", "a", "t", 0)
	skTok, _ := vlt.Store(secretKeyValue, "AWSSecretKey", "critical", "a", "t", 0)
	mapJSON := `{"access_key_id":"` + akTok + `","secret_access_key":"` + skTok + `"}`
	mapTok, _ := vlt.Store(mapJSON, "AWSCredentialMap", "critical", "a", "t", 0)
	if err := vlt.SetLabel("aws:"+profile, mapTok); err != nil {
		t.Fatal(err)
	}
	if err := vlt.SaveProfile("aws", profile, mapTok, map[string]string{"source": "~/.aws/credentials"}); err != nil {
		t.Fatal(err)
	}
	return skTok
}

// seedSSH seeds a provider that is file-delivered and has NO per-operation
// route — the only shape an agent may still assume. aws/github/git/gitlab all
// declare an agent block and are routed to the broker instead.
func seedSSH(t *testing.T, vlt *vault.Vault, instance string) {
	t.Helper()
	keyTok, _ := vlt.Store("-----BEGIN OPENSSH PRIVATE KEY-----\nc2VlZA==\n-----END OPENSSH PRIVATE KEY-----\n",
		"SSHPrivateKey", "critical", "a", "t", 0)
	mapJSON := `{"private_key":"` + keyTok + `"}`
	mapTok, _ := vlt.Store(mapJSON, "SSHCredentialMap", "critical", "a", "t", 0)
	if err := vlt.SetLabel("ssh:"+instance, mapTok); err != nil {
		t.Fatal(err)
	}
	if err := vlt.SaveProfile("ssh", instance, mapTok, map[string]string{"source": "~/.ssh/" + instance}); err != nil {
		t.Fatal(err)
	}
}

func getIdentity(t *testing.T, ts *httptest.Server, provider, profile string) (int, map[string]interface{}, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/identity?provider="+provider+"&profile="+profile, nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]interface{}
	json.Unmarshal(body, &out)
	return resp.StatusCode, out, string(body)
}

// The headline behaviour: the account number comes back without assuming the
// credential and without a network call.
func TestIdentityDerivesAccountWithoutAssuming(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	code, out, raw := getIdentity(t, ts, "aws", "default")
	if code != 200 {
		t.Fatalf("identity failed: %d %s", code, raw)
	}
	facts, _ := out["facts"].(map[string]interface{})
	if facts["account_id"] != "716969406655" {
		t.Fatalf("account_id = %v, full: %s", facts["account_id"], raw)
	}
	if out["offline"] != true {
		t.Errorf("AWS derivation must report offline=true: %s", raw)
	}
}

// THE security property: a describe must never decrypt the secret half of the
// credential. Asserting on retrieved_count proves the secret was not merely
// filtered out of the response — it was never unwrapped at all, so it never
// existed in the daemon's memory to leak.
func TestIdentityNeverDecryptsTheSecret(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	secretTok := seedAWS(t, vlt, "default", testAccount)

	before, err := vlt.Inspect(secretTok)
	if err != nil {
		t.Fatal(err)
	}

	_, _, raw := getIdentity(t, ts, "aws", "default")
	if strings.Contains(raw, secretKeyValue) {
		t.Fatalf("identity response leaked the secret access key: %s", raw)
	}

	after, err := vlt.Inspect(secretTok)
	if err != nil {
		t.Fatal(err)
	}
	if after.RetrievedCount != before.RetrievedCount {
		t.Errorf("describe decrypted the secret access key (retrieved_count %d → %d); it should never be unwrapped",
			before.RetrievedCount, after.RetrievedCount)
	}
}

// The access key id is derivation input, not output. Echoing it would scatter
// half the credential pair through terminals, logs, and CI output.
func TestIdentityDoesNotReturnTheKeyID(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	_, _, raw := getIdentity(t, ts, "aws", "default")
	if strings.Contains(raw, awsKeyFor(testAccount)) {
		t.Fatalf("identity response echoed the access key id: %s", raw)
	}
}

// A credential whose keys no longer authenticate still has an account number,
// and that is exactly when someone needs it.
func TestIdentityAnswersForDeadCredentials(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "revoked-profile", testAccount)

	code, out, raw := getIdentity(t, ts, "aws", "revoked-profile")
	if code != 200 {
		t.Fatalf("identity must not depend on the credential being valid: %d %s", code, raw)
	}
	facts, _ := out["facts"].(map[string]interface{})
	if facts["account_id"] != "716969406655" {
		t.Errorf("account_id = %v", facts["account_id"])
	}
}

// Nothing may be persisted. A cache in the plaintext metadata column would put
// account numbers in a file whose whole promise is that it is inert without the
// keychain key — and would give an attacker who can write metadata a way to
// make whoami lie about which account a credential belongs to.
func TestIdentityPersistsNothing(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	if code, _, raw := getIdentity(t, ts, "aws", "default"); code != 200 {
		t.Fatalf("identity failed: %d %s", code, raw)
	}

	p, err := vlt.GetProfile("aws", "default")
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Metadata {
		if k != "source" {
			t.Errorf("describe persisted %q=%q; it must leave no trace in plaintext metadata", k, v)
		}
	}
	if strings.Contains(p.Metadata["source"], "716969406655") {
		t.Error("account number written into profile metadata")
	}
}

// A denied caller must not be able to use error messages to learn which
// providers or profiles exist. The gate runs before any existence check.
func TestIdentityGatesBeforeDisclosingExistence(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: allow
rules:
  - action: describe
    effect: deny
    reason: "no describes"
`)
	trustBundle(t)
	seedAWS(t, vlt, "real", testAccount)

	realCode, _, realBody := getIdentity(t, ts, "aws", "real")
	fakeCode, _, fakeBody := getIdentity(t, ts, "aws", "invented")
	if realCode != 403 || fakeCode != 403 {
		t.Fatalf("both must be 403; got real=%d fake=%d", realCode, fakeCode)
	}
	if realBody != fakeBody {
		t.Errorf("denial distinguishes a real profile from an invented one:\n real: %s\n fake: %s", realBody, fakeBody)
	}

	// And a provider with no identity contract at all must look the same.
	ghCode, _, ghBody := getIdentity(t, ts, "github", "inferlabs")
	if ghCode != 403 || ghBody != realBody {
		t.Errorf("denial leaks which providers declare a contract: %d %s", ghCode, ghBody)
	}
}

// A provider with no identity contract has nothing to derive, and must say so
// rather than falling back to some generic path.
func TestIdentityRejectsProviderWithoutContract(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	tok, _ := vlt.Store("ghp_x", "GitHubToken", "critical", "a", "t", 0)
	vlt.SetLabel("github:inferlabs", tok)

	code, _, raw := getIdentity(t, ts, "github", "inferlabs")
	if code != 404 {
		t.Fatalf("expected 404 for a provider with no identity contract, got %d %s", code, raw)
	}
}

// An untrusted template must not drive a derivation. The template declares
// which fields are secret, and that declaration decides what gets decrypted, so
// an edited or freshly dropped file must be re-approved first.
func TestIdentityRequiresATrustedTemplate(t *testing.T) {
	ts, vlt := newTestServer(t)
	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	useUnsignedBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	code, _, raw := getIdentity(t, ts, "aws", "default")
	if code != 403 {
		t.Fatalf("an untrusted template must not be used to describe: %d %s", code, raw)
	}
	if !strings.Contains(raw, "not trusted") {
		t.Errorf("error should name the cause: %s", raw)
	}
}

// A template that marks the contract's input field secret must be refused, not
// obeyed. This is the hostile-template case: reclassifying a field must never
// talk the daemon into decrypting a secret for a describe.
func TestIdentityRefusesWhenContractInputIsDeclaredSecret(t *testing.T) {
	tdir := t.TempDir()
	os.WriteFile(filepath.Join(tdir, "aws.yaml"), []byte(`
kind: provider
name: aws
version: 1
credential:
  fields:
    access_key_id:     {secret: true}
    secret_access_key: {secret: true}
deliver:
  - mode: file
    name: "aws-{instance}.creds"
    render: ["[{instance}]", "aws_access_key_id = {access_key_id}"]
    env: {AWS_SHARED_CREDENTIALS_FILE: "{path}"}
  - mode: describe
    contract: aws-access-key-account-id
    map: {account_id: account_id}
`), 0600)
	t.Setenv("AKASHA_TEMPLATES_PATH", tdir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	ts, vlt := newTestServer(t)
	trustBundle(t)
	secretTok := seedAWS(t, vlt, "default", testAccount)

	before, _ := vlt.Inspect(secretTok)
	code, _, raw := getIdentity(t, ts, "aws", "default")
	if code != 409 {
		t.Fatalf("expected refusal when the contract's input is declared secret, got %d %s", code, raw)
	}
	after, _ := vlt.Inspect(secretTok)
	if after.RetrievedCount != before.RetrievedCount {
		t.Error("refused describe still decrypted a secret")
	}
}

// Describing a source-backed provider would fetch the whole credential from an
// upstream manager over the network — the opposite of what DESCRIBE promises.
func TestIdentityRefusesSourceBackedProviders(t *testing.T) {
	tdir := t.TempDir()
	os.WriteFile(filepath.Join(tdir, "aws.yaml"), []byte(`
kind: provider
name: aws
version: 1
credential:
  fields:
    access_key_id:     {secret: false}
    secret_access_key: {secret: true}
source:
  - backend: onepassword-cli
    ref: "op://Eng/aws/{instance}/credential"
    map: {value: access_key_id}
deliver:
  - mode: file
    name: "aws-{instance}.creds"
    render: ["[{instance}]", "aws_access_key_id = {access_key_id}"]
    env: {AWS_SHARED_CREDENTIALS_FILE: "{path}"}
  - mode: describe
    contract: aws-access-key-account-id
    map: {account_id: account_id}
`), 0600)
	t.Setenv("AKASHA_TEMPLATES_PATH", tdir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	ts, _ := newTestServer(t)
	trustBundle(t)

	code, _, raw := getIdentity(t, ts, "aws", "default")
	if code != 409 {
		t.Fatalf("expected refusal for a source-backed provider, got %d %s", code, raw)
	}
	if !strings.Contains(raw, "network") {
		t.Errorf("error should explain the escalation it is avoiding: %s", raw)
	}
}

// A blanket critical-risk deny must cover describes. If a new action slipped in
// below an operator's existing threshold, upgrading Akasha would silently widen
// what their unchanged policy file permits.
func TestIdentityCoveredByBlanketCriticalDeny(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: allow
rules:
  - category: Credential
    min_risk: critical
    effect: deny
    reason: "locked down"
`)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	code, _, raw := getIdentity(t, ts, "aws", "default")
	if code != 403 {
		t.Fatalf("a blanket critical deny must cover identity, got %d %s", code, raw)
	}
}

// ...and opting back in is one rule, so the frictionless path stays available.
func TestIdentityAllowRuleRestoresFrictionlessDescribe(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: allow
rules:
  - action: describe
    effect: allow
    reason: "describes are fine"
  - category: Credential
    min_risk: critical
    effect: deny
    reason: "everything else locked down"
`)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	code, out, raw := getIdentity(t, ts, "aws", "default")
	if code != 200 {
		t.Fatalf("an explicit identity allow should work: %d %s", code, raw)
	}
	facts, _ := out["facts"].(map[string]interface{})
	if facts["account_id"] != "716969406655" {
		t.Errorf("account_id = %v", facts["account_id"])
	}
}

func TestIdentityRequiresProviderAndProfile(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _, _ := getIdentity(t, ts, "", ""); code != 400 {
		t.Errorf("expected 400 without provider/profile, got %d", code)
	}
}

// The template — not the daemon, not the contract — decides what is revealed.
// This provider's disclosure list names only account_id, so key_type must not
// come back even though the contract computed it.
func TestIdentityRevealsOnlyWhatTheTemplateLists(t *testing.T) {
	tdir := t.TempDir()
	os.WriteFile(filepath.Join(tdir, "aws.yaml"), []byte(`
kind: provider
name: aws
version: 1
credential:
  fields:
    access_key_id:     {secret: false}
    secret_access_key: {secret: true}
deliver:
  - mode: file
    name: "aws-{instance}.creds"
    render: ["[{instance}]", "aws_access_key_id = {access_key_id}"]
    env: {AWS_SHARED_CREDENTIALS_FILE: "{path}"}
  - mode: describe
    contract: aws-access-key-account-id
    map: {account_id: account_id}
`), 0600)
	t.Setenv("AKASHA_TEMPLATES_PATH", tdir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	code, out, raw := getIdentity(t, ts, "aws", "default")
	if code != 200 {
		t.Fatalf("identity failed: %d %s", code, raw)
	}
	facts, _ := out["facts"].(map[string]interface{})
	if facts["account_id"] != "716969406655" {
		t.Errorf("account_id = %v", facts["account_id"])
	}
	if _, leaked := facts["key_type"]; leaked {
		t.Errorf("daemon revealed a fact the template did not list: %s", raw)
	}
}

// A template may name the disclosed fact itself, so the vocabulary a consumer
// sees belongs to the provider rather than to the daemon's contract registry.
func TestIdentityHonoursTemplateFactNames(t *testing.T) {
	tdir := t.TempDir()
	os.WriteFile(filepath.Join(tdir, "aws.yaml"), []byte(`
kind: provider
name: aws
version: 1
credential:
  fields:
    access_key_id:     {secret: false}
    secret_access_key: {secret: true}
deliver:
  - mode: file
    name: "aws-{instance}.creds"
    render: ["[{instance}]", "aws_access_key_id = {access_key_id}"]
    env: {AWS_SHARED_CREDENTIALS_FILE: "{path}"}
  - mode: describe
    contract: aws-access-key-account-id
    map: {aws_account_number: account_id}
`), 0600)
	t.Setenv("AKASHA_TEMPLATES_PATH", tdir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "appr.json"))
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "default", testAccount)

	_, out, raw := getIdentity(t, ts, "aws", "default")
	facts, _ := out["facts"].(map[string]interface{})
	if facts["aws_account_number"] != "716969406655" {
		t.Errorf("template-chosen fact name not honoured: %s", raw)
	}
}

// ─── /label/delete ────────────────────────────────────────────────────────

func postJSON(t *testing.T, ts *httptest.Server, path string, body map[string]string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := ts.Client().Post(ts.URL+path, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestLabelDeleteRemovesTheName(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("v", "APIKey", "high", "a", "t", 0)
	vlt.SetLabel("svc:x", tok)

	code, body := postJSON(t, ts, "/label/delete", map[string]string{"name": "svc:x"})
	if code != 200 {
		t.Fatalf("delete failed: %d %s", code, body)
	}
	if _, err := vlt.GetLabel("svc:x"); err == nil {
		t.Error("label still resolves after delete")
	}
}

// Unbinding is gated as a bind: an operator who controls who may repoint a
// credential's name must also control who may remove it, or the control is
// incoherent.
func TestLabelDeleteIsGatedAsBind(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: allow
rules:
  - action: bind
    effect: deny
    reason: "bindings are frozen"
`)
	tok, _ := vlt.Store("v", "APIKey", "high", "a", "t", 0)
	vlt.SetLabel("svc:x", tok)

	code, body := postJSON(t, ts, "/label/delete", map[string]string{"name": "svc:x"})
	if code != 403 {
		t.Fatalf("expected 403 under a bind deny, got %d %s", code, body)
	}
	if _, err := vlt.GetLabel("svc:x"); err != nil {
		t.Error("a denied delete must not have removed the label")
	}
}

// A denied caller must not learn which labels exist from the error.
func TestLabelDeleteGatesBeforeDisclosingExistence(t *testing.T) {
	ts, vlt, _ := newPolicyTestServer(t, `
default: allow
rules:
  - action: bind
    effect: deny
    reason: "bindings are frozen"
`)
	tok, _ := vlt.Store("v", "APIKey", "high", "a", "t", 0)
	vlt.SetLabel("svc:real", tok)

	realCode, realBody := postJSON(t, ts, "/label/delete", map[string]string{"name": "svc:real"})
	fakeCode, fakeBody := postJSON(t, ts, "/label/delete", map[string]string{"name": "svc:invented"})
	if realCode != 403 || fakeCode != 403 {
		t.Fatalf("both must be 403: real=%d fake=%d", realCode, fakeCode)
	}
	if realBody != fakeBody {
		t.Errorf("denial distinguishes a real label from an invented one:\n real: %s\n fake: %s", realBody, fakeBody)
	}
}

func TestLabelDeleteUnknownNameIs404(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, body := postJSON(t, ts, "/label/delete", map[string]string{"name": "svc:nope"}); code != 404 {
		t.Errorf("expected 404, got %d %s", code, body)
	}
}

// Asking "what would removing this name affect?" must not decrypt the
// credential. The obvious implementation — resolving via /credential/retrieve — returns
// the raw secret, so a confirmation prompt would read the very thing it is
// asking whether to forget. retrieved_count proves nothing was unwrapped.
func TestLabelDeletePreviewNeverDecrypts(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("super-secret-value", "APIKey", "critical", "a", "t", 0)
	vlt.SetLabel("svc:x", tok)
	vlt.SetLabel("svc:alias", tok)

	before, err := vlt.Inspect(tok)
	if err != nil {
		t.Fatal(err)
	}

	code, body := postJSON(t, ts, "/label/delete", map[string]string{"name": "svc:x", "preview": "true"})
	_ = code
	if strings.Contains(body, "super-secret-value") {
		t.Fatalf("preview leaked the credential: %s", body)
	}

	after, err := vlt.Inspect(tok)
	if err != nil {
		t.Fatal(err)
	}
	if after.RetrievedCount != before.RetrievedCount {
		t.Errorf("preview decrypted the credential (retrieved_count %d → %d)",
			before.RetrievedCount, after.RetrievedCount)
	}
}

// Preview must report siblings and leave the label in place.
func TestLabelDeletePreviewReportsSiblingsWithoutRemoving(t *testing.T) {
	ts, vlt := newTestServer(t)
	tok, _ := vlt.Store("v", "APIKey", "high", "a", "t", 0)
	vlt.SetLabel("svc:x", tok)
	vlt.SetLabel("svc:alias", tok)

	b, _ := json.Marshal(map[string]interface{}{"name": "svc:x", "preview": true})
	resp, err := ts.Client().Post(ts.URL+"/label/delete", "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AlsoNamed []string `json:"also_named"`
	}
	json.NewDecoder(resp.Body).Decode(&out)

	if len(out.AlsoNamed) != 1 || out.AlsoNamed[0] != "svc:alias" {
		t.Errorf("preview should report the sibling name, got %v", out.AlsoNamed)
	}
	if _, err := vlt.GetLabel("svc:x"); err != nil {
		t.Error("preview must not remove the label")
	}
}
