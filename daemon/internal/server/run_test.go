package server_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

type runEnv struct {
	ts  *httptest.Server
	vlt *vault.Vault
	dir string
}

func newRunTestServer(t *testing.T, policyYAML string) *runEnv {
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
	srv := server.New(classifier.New(nil), vlt, auditL)
	srv.SetPolicyEngine(policy.NewEngine(polPath))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); auditL.Close(); vlt.Close() })
	// `akasha run` may only be started by the human, so this env authenticates
	// as one by default — see humanServer.
	return &runEnv{ts: humanServer(t, ts, vlt), vlt: vlt, dir: dir}
}

// beginRun starts a supervised run and returns (runID, key, socket).
//
// The run dir is short on purpose: a unix socket path has a ~104-byte limit,
// and t.TempDir() under the default TMPDIR can exceed it.
func (e *runEnv) beginRun(t *testing.T, name string, assume []string) (string, string, string) {
	t.Helper()
	runDir, err := os.MkdirTemp("/tmp", "akr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runDir) })

	code, out := post(t, e.ts, "/run/begin", map[string]interface{}{
		"name": name, "assume": assume, "run_dir": runDir,
	}, "")
	if code != 200 {
		t.Fatalf("/run/begin: got %d (%v)", code, out)
	}
	return out["run_id"].(string), out["key"].(string), out["socket"].(string)
}

// runReq issues a request over the run's PRIVATE socket. That listener is where
// the capability profile applies, so tests must not go through the main one.
func runReq(t *testing.T, sock, method, path, body, key string) (int, string) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial run socket %s: %v", sock, err)
	}
	defer conn.Close()

	req := method + " " + path + " HTTP/1.0\r\nHost: localhost\r\n"
	if key != "" {
		req += "X-Akasha-Key: " + key + "\r\n"
	}
	if body != "" {
		req += "Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	req += "\r\n" + body
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}

	var raw []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}
	s := string(raw)
	status := 0
	if parts := strings.SplitN(s, " ", 3); len(parts) >= 2 {
		status, _ = strconv.Atoi(parts[1])
	}
	return status, s
}

// keyedReq issues a request to the daemon's MAIN listener under key. The run
// socket is not involved, which is the point wherever this is used.
func keyedReq(t *testing.T, ts *httptest.Server, method, path, body, key string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Akasha-Key", key)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestRunCapabilityProfile is what makes `akasha run` more than `akasha exec`.
// A launcher-side check constrains nothing — the child can reach the socket
// itself — so the daemon has to refuse these.
func TestRunCapabilityProfile(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/retrieve", `{"token":"vault://x","requesting_tool":"t"}`},
		{"POST", "/assume", `{"provider":"aws","profile":"default"}`},
		{"GET", "/credential/retrieve?name=aws:default", ""},
		{"GET", "/label/list", ""},
		{"POST", "/grant", `{"token":"vault://x","grantor_agent":"a","grantee_agent":"b"}`},
	} {
		code, _ := runReq(t, sock, tc.method, tc.path, tc.body, key)
		if code != 403 {
			t.Errorf("%s %s from a run: got %d, want 403", tc.method, tc.path, code)
		}
	}
}

// The --assume list is the capability grant, enforced server-side.
func TestRunResolveAllowlist(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	if code, _ := runReq(t, sock, "GET", "/resolve?provider=aws&instance=default", "", key); code != 403 {
		t.Errorf("ungranted provider: got %d, want 403", code)
	}
	if code, _ := runReq(t, sock, "GET", "/resolve?provider=github&instance=personal", "", key); code != 403 {
		t.Errorf("ungranted instance: got %d, want 403", code)
	}
	// Granted: must get PAST the capability gate. It then fails for lack of a
	// vaulted credential, which is fine — the gate is what is under test.
	code, body := runReq(t, sock, "GET", "/resolve?provider=github&instance=work", "", key)
	if code == 403 && strings.Contains(body, "was not launched with") {
		t.Errorf("granted provider:instance was refused by the capability gate:\n%s", body)
	}
}

// An agent must not start a run, or it launders its own policy scope by minting
// a fresh identity and evaluating against rules written for a name it chose.
func TestRunBeginRefusesVerifiedAgent(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, err := e.vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}
	runDir, _ := os.MkdirTemp("/tmp", "akr")
	defer os.RemoveAll(runDir)

	code, _ := post(t, e.ts, "/run/begin", map[string]interface{}{
		"name": "sneaky", "run_dir": runDir,
	}, key)
	if code != 403 {
		t.Fatalf("an agent started a run: got %d, want 403", code)
	}
}

// The name becomes a policy identity, so characters that break rule matching are
// refused — '/' especially, since filepath.Match's '*' does not cross it and
// `agent: "run:*"` would silently stop matching.
func TestRunNameValidation(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	runDir, _ := os.MkdirTemp("/tmp", "akr")
	defer os.RemoveAll(runDir)

	for _, bad := range []string{"", "has/slash", "has:colon", "has*star", "UPPER", strings.Repeat("x", 33), "-leading"} {
		code, _ := post(t, e.ts, "/run/begin", map[string]interface{}{
			"name": bad, "run_dir": runDir,
		}, "")
		if code != 400 {
			t.Errorf("name %q: got %d, want 400", bad, code)
		}
	}
}

// Ending a run revokes its key immediately. `akasha exec` left a materialized
// credential valid until a sweeper noticed; here the very next call fails.
func TestRunEndRevokesKey(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	runID, key, _ := e.beginRun(t, "demo", nil)

	if _, err := e.vlt.VerifyAgentKey(key); err != nil {
		t.Fatalf("run key should verify while the run is live: %v", err)
	}
	if code, _ := post(t, e.ts, "/run/end", map[string]interface{}{"run_id": runID}, ""); code != 200 {
		t.Fatalf("/run/end: got %d", code)
	}
	if _, err := e.vlt.VerifyAgentKey(key); err == nil {
		t.Fatal("the run key is still valid after the run ended")
	}
}

// A run cannot outlive the daemon, so a leftover run:* key from a daemon that
// exited badly is revoked at startup.
func TestSweepRevokesLeftoverRunKeys(t *testing.T) {
	dir := t.TempDir()
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()
	// MintReservedAgentKey: `run:` is reserved, so CreateAgentKey refuses it —
	// only the daemon may name a run identity.
	_, stale, err := vlt.MintReservedAgentKey("run:leftover")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vlt.VerifyAgentKey(stale); err != nil {
		t.Fatalf("setup: %v", err)
	}

	auditL, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditL.Close()
	server.New(classifier.New(nil), vlt, auditL) // constructing a Server runs the sweep

	if _, err := vlt.VerifyAgentKey(stale); err == nil {
		t.Fatal("a leftover run key survived daemon startup")
	}
}

// The run socket lives in the run directory, not ~/.akasha — that is what lets
// the sandbox deny the whole data directory with no hole punched in it.
func TestRunSocketIsOutsideDataDir(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, _, sock := e.beginRun(t, "demo", nil)
	if strings.Contains(sock, ".akasha") {
		t.Fatalf("run socket %q is inside the data directory", sock)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("run socket not created: %v", err)
	}
}

// Requests on the run socket are marked Sandboxed, so `sandbox: false -> deny`
// can REQUIRE a supervised launch. It is a daemon-derived fact — which listener
// accepted the connection — not anything the caller sent.
func TestSandboxMatcherRequiresSupervisedRun(t *testing.T) {
	e := newRunTestServer(t, `
rules:
  - action: broker
    sandbox: false
    effect: deny
    reason: brokering requires a supervised run
`)
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	code, body := runReq(t, sock, "GET", "/resolve?provider=github&instance=work", "", key)
	if code == 403 && strings.Contains(body, "requires a supervised run") {
		t.Fatalf("a sandboxed request was denied by a sandbox:false rule:\n%s", body)
	}

	resp, err := e.ts.Client().Get(e.ts.URL + "/resolve?provider=github&instance=work")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("unsandboxed broker: got %d, want 403", resp.StatusCode)
	}
}

// TestRunProfileFollowsIdentityNotListener is the regression this whole file
// exists for.
//
// The capability profile used to wrap the handler served on the run's PRIVATE
// SOCKET, which made "broker-only" a property of a listener rather than of the
// run. Neither sandbox confines the network — macOS logs "(allow default)",
// and the Linux bwrap invocation has no --unshare-net — so a sandboxed agent
// holding AKASHA_AGENT_KEY simply opened a TCP connection to the daemon's
// always-on loopback port and reached the unrestricted mux with the run's own
// key.
func TestRunProfileFollowsIdentityNotListener(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	// The control: the profile still applies where it always did.
	if code, body := runReq(t, sock, "POST", "/retrieve", `{"token":"vault://x","requesting_tool":"t"}`, key); code != 403 {
		t.Fatalf("/retrieve on the run socket: got %d, want 403\n%s", code, body)
	}

	// The bypass: the same identity, off the run socket entirely.
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/retrieve", `{"token":"vault://x","requesting_tool":"t"}`},
		{"POST", "/assume", `{"provider":"aws","profile":"default"}`},
		{"GET", "/credential/retrieve?name=aws:default", ""},
		{"GET", "/label/list", ""},
		{"POST", "/grant", `{"token":"vault://x","grantor_agent":"a","grantee_agent":"b"}`},
		{"GET", "/resolve?provider=aws&instance=default", ""},
	} {
		code, body := keyedReq(t, e.ts, tc.method, tc.path, tc.body, key)
		if code != 403 {
			t.Errorf("BYPASS: %s %s with the run key on the main listener got %d, want 403 — "+
				"the capability profile did not follow the run identity\n%s", tc.method, tc.path, code, body)
		}
	}
}

// A run's identity must keep meaning "sandboxed" wherever it calls from, or a
// `sandbox: false -> deny` rule is escaped by the same change of listener.
func TestRunIsSandboxedOnEveryListener(t *testing.T) {
	e := newRunTestServer(t, `
rules:
  - action: broker
    sandbox: false
    effect: deny
    reason: brokering requires a supervised run
`)
	_, key, _ := e.beginRun(t, "demo", []string{"github:work"})

	// The control: the human CLI is not sandboxed and is denied.
	resp, err := e.ts.Client().Get(e.ts.URL + "/resolve?provider=github&instance=work")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("unsandboxed broker on the main listener: got %d, want 403", resp.StatusCode)
	}

	code, body := keyedReq(t, e.ts, "GET", "/resolve?provider=github&instance=work", "", key)
	if code == 403 && strings.Contains(body, "requires a supervised run") {
		t.Fatalf("BYPASS: a run calling the main listener was judged unsandboxed:\n%s", body)
	}
}

// The run socket is inside the sandbox, so reaching it is not an identity.
func TestRunSocketRefusesKeylessCaller(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	// The control: the run's own key authenticates.
	if code, body := runReq(t, sock, "GET", "/resolve?provider=github&instance=work", "", key); code == 401 {
		t.Fatalf("the run's own key was refused on its own socket:\n%s", body)
	}

	code, body := runReq(t, sock, "GET", "/resolve?provider=github&instance=work", "", "")
	if code != 401 {
		t.Fatalf("BYPASS: a keyless caller on the run socket got %d, want 401\n%s", code, body)
	}
}

// TestRunSocketRefusesForeignKey: Run.Key was minted, returned, and then never
// compared to anything — only KeyID was, for revocation. So the one endpoint a
// sandboxed agent is allowed to reach accepted ANY valid vault key, including
// the human CLI's, whose capabilities are unrestricted.
func TestRunSocketRefusesForeignKey(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})
	_, other, err := e.vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	// The control: the run's own key is served.
	if code, body := runReq(t, sock, "GET", "/resolve?provider=github&instance=work", "", key); code == 401 {
		t.Fatalf("the run's own key was refused on its own socket:\n%s", body)
	}

	code, body := runReq(t, sock, "GET", "/resolve?provider=github&instance=work", "", other)
	if code != 401 {
		t.Fatalf("BYPASS: another agent's key was accepted on run demo's socket, got %d, want 401\n%s", code, body)
	}
	for _, want := range []string{"belongs to run", "demo"} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, body)
		}
	}
}

// A run must not mint a run: /run/begin carries its own --assume list, so a run
// that could start one would write itself a wider grant than the human gave it.
func TestRunCannotBeginAnotherRun(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})
	runDir, err := os.MkdirTemp("/tmp", "akr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runDir)

	body := fmt.Sprintf(`{"name":"wider","assume":["aws:prod"],"run_dir":%q}`, runDir)
	if code, out := runReq(t, sock, "POST", "/run/begin", body, key); code != 403 {
		t.Errorf("BYPASS: a run started a run over the run socket, got %d, want 403\n%s", code, out)
	}
	if code, out := keyedReq(t, e.ts, "POST", "/run/begin", body, key); code != 403 {
		t.Errorf("BYPASS: a run started a run on the main listener, got %d, want 403\n%s", code, out)
	}
}

// TestRunCannotWriteToVault: the profile only ever covered the read side. The
// write side is the more valuable half — a run that re-points aws:default at a
// credential it controls redirects every later assume, git push and
// credential_process the human makes, without reading a secret itself.
func TestRunCannotWriteToVault(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})
	tok, err := e.vlt.Store("x", "Credential", "high", "seed", "seed", 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/put", `{"label":"aws:default","fields":{"k":"v"}}`},
		{"POST", "/label/set", fmt.Sprintf(`{"name":"aws:default","token":%q}`, tok)},
		{"POST", "/label/delete", `{"name":"aws:default"}`},
		{"POST", "/profile/save", fmt.Sprintf(`{"provider":"aws","profile":"default","token":%q}`, tok)},
		{"POST", "/store", `{"agent_id":"a","tool_name":"t","content":"x","category":"SSN","risk":"high"}`},
		{"POST", "/vault/purge", `{}`},
	} {
		if code, out := runReq(t, sock, tc.method, tc.path, tc.body, key); code != 403 {
			t.Errorf("BYPASS: %s %s from a run got %d, want 403\n%s", tc.method, tc.path, code, out)
		}
		if code, out := keyedReq(t, e.ts, tc.method, tc.path, tc.body, key); code != 403 {
			t.Errorf("BYPASS: %s %s from a run on the main listener got %d, want 403\n%s",
				tc.method, tc.path, code, out)
		}
	}
	// The control: the human may still write.
	if code, _ := post(t, e.ts, "/label/set", map[string]string{"name": "aws:default", "token": tok}, ""); code != 200 {
		t.Errorf("the human CLI can no longer bind a label: got %d, want 200", code)
	}
}

// /wrap is the one vault write a run keeps. It mints a token and binds no name,
// so it cannot re-point a credential, and it is how an SDK agent keeps a secret
// out of the model's context — the protective path must not be refused inside
// the tier that exists to be the safest place to run.
func TestRunMayStillWrapSecrets(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	body := `{"agent_id":"a","tool_name":"send_email","content":"SSN 429-21-0001"}`
	for _, tc := range []struct {
		where string
		code  int
		out   string
	}{
		{"run socket", func() int { c, _ := runReq(t, sock, "POST", "/wrap", body, key); return c }(), ""},
		{"main listener", func() int { c, _ := keyedReq(t, e.ts, "POST", "/wrap", body, key); return c }(), ""},
	} {
		if tc.code != 200 {
			t.Errorf("/wrap from a run on the %s got %d, want 200 — the protective call must stay open", tc.where, tc.code)
		}
	}

	// And it really vaulted: the secret is gone from the content handed back.
	_, out := runReq(t, sock, "POST", "/wrap", body, key)
	if strings.Contains(out, "429-21-0001") {
		t.Errorf("/wrap returned the raw secret to a run:\n%s", out)
	}
}

// Ending a run revokes its key, so an unscoped /run/end is a kill switch any
// authenticated process could pull on anyone else's run.
func TestRunEndRefusesForeignCaller(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	runID, key, _ := e.beginRun(t, "demo", nil)
	_, other, err := e.vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatal(err)
	}

	if code, _ := post(t, e.ts, "/run/end", map[string]string{"run_id": runID}, other); code != 403 {
		t.Fatalf("BYPASS: another agent ended someone else's run, got %d, want 403", code)
	}
	if _, err := e.vlt.VerifyAgentKey(key); err != nil {
		t.Fatalf("BYPASS: the run's key was revoked by a caller that does not own the run: %v", err)
	}

	// The control: the supervisor that started it still can.
	if code, _ := post(t, e.ts, "/run/end", map[string]string{"run_id": runID}, ""); code != 200 {
		t.Fatalf("the run's own supervisor could not end it: got %d, want 200", code)
	}
}

// The run socket is created 0777 &^ umask, which on a default umask is
// world-connectable — and it is the endpoint that speaks for the run.
func TestRunSocketIsPrivateToThisUser(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, _, sock := e.beginRun(t, "demo", nil)

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("run socket mode is %04o, want 0600 — any local account can open it", perm)
	}
}

// run_dir was checked only with filepath.IsAbs, so the daemon would create the
// run's socket in a directory whose owner could unlink and replace it.
func TestRunDirMustBePrivate(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	shared, err := os.MkdirTemp("/tmp", "akr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shared)
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}

	code, out := post(t, e.ts, "/run/begin", map[string]interface{}{
		"name": "demo", "run_dir": shared,
	}, "")
	if code != 400 {
		t.Fatalf("BYPASS: a world-writable run_dir was accepted, got %d (%v)", code, out)
	}

	// The control: a private directory still works.
	private, err := os.MkdirTemp("/tmp", "akr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	if code, out := post(t, e.ts, "/run/begin", map[string]interface{}{
		"name": "demo", "run_dir": private,
	}, ""); code != 200 {
		t.Fatalf("a 0700 run_dir was refused: got %d (%v)", code, out)
	}
}
