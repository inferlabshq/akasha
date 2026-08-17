package provision

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recorder is a stand-in daemon: it records every request the client makes and
// hands back the canned response registered for that path.
type recorder struct {
	mu     sync.Mutex
	calls  []call
	status map[string]int         // path → status to return (default 200)
	body   map[string]interface{} // path → JSON body to return
	tokens int
}

type call struct {
	path    string
	payload map[string]interface{}
}

func newRecorder() *recorder {
	return &recorder{status: map[string]int{}, body: map[string]interface{}{}}
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	payload := map[string]interface{}{}
	json.Unmarshal(raw, &payload)

	r.mu.Lock()
	r.calls = append(r.calls, call{path: req.URL.Path, payload: payload})
	code := r.status[req.URL.Path]
	out, custom := r.body[req.URL.Path]
	if !custom && req.URL.Path == "/store" {
		r.tokens++
		out = map[string]interface{}{"token": tokenFor(r.tokens)}
	}
	r.mu.Unlock()

	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	if out == nil {
		out = map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(out)
}

func tokenFor(n int) string {
	return "tok_" + string(rune('a'+n-1))
}

func (r *recorder) pathsHit() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ps []string
	for _, c := range r.calls {
		ps = append(ps, c.path)
	}
	return ps
}

func (r *recorder) firstTo(path string) (map[string]interface{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c.path == path {
			return c.payload, true
		}
	}
	return nil, false
}

func (r *recorder) countTo(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c.path == path {
			n++
		}
	}
	return n
}

func newTestClient(t *testing.T, r *recorder) *Client {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return New(srv.URL, "akasha-test")
}

// GUARANTEE: the label VaultFinding mints is exactly "<provider>:<instance>".
// Everything downstream — `akasha assume`, the git/aws helpers, the agent env
// stubs — resolves credentials by that string, so a change in composition
// silently mislabels every credential discovery finds.
func TestVaultFindingLabelComposition(t *testing.T) {
	r := newRecorder()
	c := newTestClient(t, r)

	err := c.VaultFinding("aws", "prod", map[string]string{
		"access_key_id":     "AKIA123",
		"secret_access_key": "s3cret",
	}, "~/.aws/credentials")
	if err != nil {
		t.Fatalf("VaultFinding: %v", err)
	}

	// One /store per field, plus one for the credential map itself.
	if got := r.countTo("/store"); got != 3 {
		t.Fatalf("expected 3 /store calls (2 fields + map), got %d: %v", got, r.pathsHit())
	}

	label, ok := r.firstTo("/label/set")
	if !ok {
		t.Fatalf("no /label/set call: %v", r.pathsHit())
	}
	if label["name"] != "aws:prod" {
		t.Fatalf("label name = %q, want %q", label["name"], "aws:prod")
	}
	mapTok, _ := label["token"].(string)
	if mapTok == "" {
		t.Fatal("label points at no token")
	}

	profile, ok := r.firstTo("/profile/save")
	if !ok {
		t.Fatalf("no /profile/save call: %v", r.pathsHit())
	}
	if profile["provider"] != "aws" || profile["profile"] != "prod" {
		t.Fatalf("profile row = %v", profile)
	}
	// The label and the profile row must point at the SAME map token, or
	// `akasha assume` and the cloud queries resolve to different credentials.
	if profile["token"] != mapTok {
		t.Fatalf("profile token %v != label token %v", profile["token"], mapTok)
	}
	meta, _ := profile["metadata"].(map[string]interface{})
	if meta["source"] != "~/.aws/credentials" {
		t.Fatalf("metadata source = %v", meta["source"])
	}
}

// The plaintext field values are vaulted individually; the map that the label
// points at holds tokens, never the secrets themselves.
func TestVaultFindingStoresTokensNotSecrets(t *testing.T) {
	r := newRecorder()
	c := newTestClient(t, r)

	if err := c.VaultFinding("git", "github.com", map[string]string{"token": "ghp_secret"}, "~/.git-credentials"); err != nil {
		t.Fatalf("VaultFinding: %v", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var mapContent string
	for _, cl := range r.calls {
		if cl.path != "/store" {
			continue
		}
		if cl.payload["category"] == "git-credentialMap" {
			mapContent, _ = cl.payload["content"].(string)
		}
		if cl.payload["agent_id"] != "akasha-test" {
			t.Errorf("audit attribution lost: agent_id = %v", cl.payload["agent_id"])
		}
		if cl.payload["tool_name"] != "akasha_provision" {
			t.Errorf("tool_name = %v", cl.payload["tool_name"])
		}
	}
	if mapContent == "" {
		t.Fatalf("no credential-map store under category git-credentialMap")
	}
	if strings.Contains(mapContent, "ghp_secret") {
		t.Fatalf("credential map carries the plaintext secret: %s", mapContent)
	}
	var resolved map[string]string
	if err := json.Unmarshal([]byte(mapContent), &resolved); err != nil {
		t.Fatalf("credential map is not a {field: token} object: %s", mapContent)
	}
	if !strings.HasPrefix(resolved["token"], "tok_") {
		t.Fatalf("field not mapped to a vault token: %v", resolved)
	}
}

// GUARANTEE: an empty field map is refused before anything is written. A
// finding with no fields would otherwise mint a label pointing at an empty
// credential map — a name that resolves, and yields nothing.
func TestVaultFindingRefusesEmptyFields(t *testing.T) {
	r := newRecorder()
	c := newTestClient(t, r)

	err := c.VaultFinding("aws", "prod", map[string]string{}, "template")
	if err == nil {
		t.Fatal("expected a refusal for a finding with no fields")
	}
	if !strings.Contains(err.Error(), "aws:prod") {
		t.Errorf("error should name the finding: %v", err)
	}
	if got := r.pathsHit(); len(got) != 0 {
		t.Fatalf("nothing should have been sent to the daemon, got %v", got)
	}

	if err := c.VaultFinding("aws", "prod", nil, "template"); err == nil {
		t.Fatal("a nil field map must be refused too")
	}
}

// A daemon that rejects the request must surface as an error, not a silently
// half-provisioned credential.
func TestPostReportsNonOKStatus(t *testing.T) {
	r := newRecorder()
	r.status["/store"] = http.StatusForbidden
	c := newTestClient(t, r)

	err := c.VaultFinding("aws", "prod", map[string]string{"access_key_id": "AKIA123"}, "template")
	if err == nil {
		t.Fatal("expected an error when the daemon returns 403")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "/store") {
		t.Errorf("error should name the path and status: %v", err)
	}
	// The label must not be minted for a credential that was never vaulted.
	if r.countTo("/label/set") != 0 {
		t.Error("a label was set despite the store failing")
	}
}

// A failed label must abort before the profile row is written, so the two
// never disagree about which token a name resolves to.
func TestVaultFindingStopsAtFailedLabel(t *testing.T) {
	r := newRecorder()
	r.status["/label/set"] = http.StatusInternalServerError
	c := newTestClient(t, r)

	if err := c.VaultFinding("aws", "prod", map[string]string{"access_key_id": "AKIA123"}, "template"); err == nil {
		t.Fatal("expected an error when /label/set fails")
	}
	if r.countTo("/profile/save") != 0 {
		t.Error("profile row written despite the label failing")
	}
}

// A 200 with no token is a daemon that did not vault anything; treating it as
// success would label an empty string.
func TestStoreRequiresAToken(t *testing.T) {
	r := newRecorder()
	r.body["/store"] = map[string]interface{}{"ok": true}
	c := newTestClient(t, r)

	_, err := c.StoreMap("aws-credential", map[string]string{"access_key_id": "AKIA123"})
	if err == nil {
		t.Fatal("expected an error when the daemon returns no token")
	}
	if !strings.Contains(err.Error(), "access_key_id") {
		t.Errorf("error should name the field that failed: %v", err)
	}
}

// GUARANTEE: the provisioning client never routes through a proxy. Its traffic
// is loopback-only and carries plaintext credentials on the way into the vault;
// an HTTPS_PROXY/HTTP_PROXY in the environment (or a corporate interception
// proxy) must not get a chance to see or redirect it. Go's default transport
// consults the environment, so this has to stay an explicit nil.
func TestTransportIsProxyFree(t *testing.T) {
	c := NewLocal("akasha-test")

	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, not a configured *http.Transport", c.http.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("Transport.Proxy must stay nil — an env proxy would otherwise see credential traffic")
	}
	if c.http.Timeout == 0 {
		t.Error("client must not wait forever on an unresponsive daemon")
	}
	if !strings.HasPrefix(c.base, "http://127.0.0.1:") {
		t.Errorf("local client should target loopback by IP, got %q", c.base)
	}
}

// PurgeOrphans is fire-and-forget by design, but it must still reach the
// daemon — and must not panic when the daemon is unreachable.
func TestPurgeOrphans(t *testing.T) {
	r := newRecorder()
	c := newTestClient(t, r)
	c.PurgeOrphans()
	if r.countTo("/vault/purge") != 1 {
		t.Fatalf("purge not sent: %v", r.pathsHit())
	}

	// No daemon listening: a closed port must be swallowed, not fatal.
	dead := New("http://127.0.0.1:1", "akasha-test")
	dead.PurgeOrphans()
}

// A daemon that is not listening surfaces as an error rather than a hang or a
// panic — discover runs against a daemon that may have just been stopped.
func TestVaultFindingUnreachableDaemon(t *testing.T) {
	c := New("http://127.0.0.1:1", "akasha-test")
	if err := c.VaultFinding("aws", "prod", map[string]string{"k": "v"}, "template"); err == nil {
		t.Fatal("expected an error against an unreachable daemon")
	}
}
