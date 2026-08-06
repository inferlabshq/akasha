package server_test

import (
	"fmt"
	"net"
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
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{})
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
	return &runEnv{ts: ts, vlt: vlt, dir: dir}
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

// TestRunCapabilityProfile is what makes `akasha run` more than `akasha exec`.
// A launcher-side check constrains nothing — the child can reach the socket
// itself — so the daemon has to refuse these.
func TestRunCapabilityProfile(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	_, key, sock := e.beginRun(t, "demo", []string{"github:work"})

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/retrieve", `{"token":"vault://x","requesting_tool":"t"}`},
		{"POST", "/assume", `{"provider":"aws","profile":"default"}`},
		{"GET", "/label/get?name=aws:default", ""},
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
	vlt, err := vault.Open(filepath.Join(dir, "vault.db"), vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer vlt.Close()
	_, stale, err := vlt.CreateAgentKey("run:leftover")
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

var _ = fmt.Sprintf
