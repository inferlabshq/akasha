package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// A "run" is a supervised agent launch: `akasha run <name> -- <command>`.
//
// The registry lives in the daemon rather than the CLI because that is the only
// place a constraint can actually hold. A check in the launcher constrains
// nothing — the process being launched can reach the socket directly and issue
// its own well-formed calls. Without this file, `akasha run` would be
// `akasha exec` wearing a costume.
//
// What the daemon adds:
//
//   - a per-run identity (run:<name>) with its own key, so policy can name the
//     run and revocation is per-run;
//   - a CAPABILITY PROFILE that is strictly narrower than the policy file: a run
//     may broker credentials it was launched with, and nothing else. This is
//     what makes "broker-only" true rather than advisory;
//   - a control connection whose loss ends the run, so killing the supervisor
//     revokes the credentials rather than leaving them live for a TTL.
//
// Runs are in-memory only: a run cannot outlive the daemon, which is the right
// semantics and avoids a schema change.

const ctxRun ctxKey = "run"

// Run is one supervised launch.
type Run struct {
	ID      string
	Name    string
	AgentID string // "run:<name>"
	KeyID   string
	Key     string // minted plaintext; returned once, and the only key the run socket accepts

	// Owner is the verified identity that started the run — the one caller
	// allowed to attach to it or end it. Without it any authenticated process
	// could end someone else's run (revoking its credentials mid-flight) or
	// take over its control connection.
	Owner string

	// Allow is the capability grant: the provider:instance pairs this run was
	// launched with. It can only ever NARROW what policy permits.
	Allow map[string]bool

	Deadline time.Time
	Sock     string

	ln       net.Listener
	attached bool
	done     chan struct{}
	once     sync.Once
}

// end tears the run down exactly once.
func (r *Run) end() {
	r.once.Do(func() {
		if r.ln != nil {
			r.ln.Close()
		}
		close(r.done)
	})
}

// runNameOK bounds the policy label.
//
// ':' is the run: namespace separator. '/' matters because policy globs use
// filepath.Match, whose '*' does not cross a separator — a slash would silently
// break `agent: "run:*"` rules. '*' and '?' must never appear in an identity.
func runNameOK(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '-' || r == '.' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// checkRunDir refuses a directory the daemon should not create a socket in.
//
// The socket in there is the run's whole authority surface, so a directory
// another user can write to is one where that socket can be unlinked and
// replaced with something the agent talks to instead. IsAbs alone said nothing
// about who owns the path.
func checkRunDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("run_dir %s cannot be read — the run's socket is created inside it: %v\n"+
			"  mkdir -p %s && chmod 0700 %s", dir, err, dir, dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("run_dir %s is not a directory — the run's socket is created inside it", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("run_dir %s sits on a filesystem that reports no ownership, so the run socket "+
			"cannot be kept private — use a directory under your home or /tmp", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("run_dir %s is owned by uid %d, not by you (uid %d) — its owner could replace the "+
			"run socket with their own\n  Use a directory you own, e.g. `mktemp -d`", dir, st.Uid, os.Getuid())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("run_dir %s is mode %04o, so group or other can replace the run socket inside it\n"+
			"  chmod 0700 %s", dir, perm, dir)
	}
	return nil
}

type beginRunRequest struct {
	Name       string   `json:"name"`
	Assume     []string `json:"assume,omitempty"`
	RunDir     string   `json:"run_dir"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

type beginRunResponse struct {
	RunID   string `json:"run_id"`
	AgentID string `json:"agent_id"`
	Key     string `json:"key"`
	Socket  string `json:"socket"`
}

func (s *Server) handleRunBegin(w http.ResponseWriter, r *http.Request) {
	// An AGENT must not be able to start a run.
	//
	// Otherwise a compromised agent launders its own policy scope: mint
	// run:whatever, get a fresh identity, and evaluate against rules written for
	// a name it chose.
	//
	// This used to test "did the caller present an agent key?", which an agent
	// defeated by unsetting AKASHA_AGENT_KEY — the check was drift protection
	// rather than an authorization check, and was documented as such. It now
	// requires an affirmative CLI identity, so dropping the key fails the gate
	// instead of passing it. (The remediation text used to SUGGEST unsetting the
	// variable, which was advice to take the bypass.)
	if !isHuman(r) {
		http.Error(w, "akasha run must be started by you, not by an agent — this request did not present the "+
			"local CLI's key. Run it from your own shell; if AKASHA_AGENT_KEY is set there, this session belongs "+
			"to an agent harness and you should start the run from a plain terminal instead.", http.StatusForbidden)
		return
	}

	var req beginRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !runNameOK(req.Name) {
		http.Error(w, "run name must be 1-32 chars of [a-z0-9] plus . _ - (no ':', '/', '*' or '?'), "+
			"because it becomes a policy identity and those characters break rule matching", http.StatusBadRequest)
		return
	}
	runDir := filepath.Clean(req.RunDir)
	if req.RunDir == "" || !filepath.IsAbs(runDir) {
		http.Error(w, "run_dir must be an absolute path", http.StatusBadRequest)
		return
	}
	if err := checkRunDir(runDir); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate the grant server-side, not just in the CLI.
	allow := map[string]bool{}
	for _, a := range req.Assume {
		provider, instance, ok := strings.Cut(a, ":")
		if !ok || provider == "" || instance == "" {
			http.Error(w, fmt.Sprintf("bad --assume %q: want provider:instance", a), http.StatusBadRequest)
			return
		}
		allow[provider+":"+instance] = true
	}

	// MintReservedAgentKey, not CreateAgentKey: `run:` is a reserved namespace
	// that CreateAgentKey refuses, precisely so no caller can mint itself a run
	// identity and inherit rules written for one. The daemon assigning the name
	// here is what makes it trustworthy.
	agentID := vault.RunIdentityPrefix + req.Name
	keyID, key, err := s.vlt.MintReservedAgentKey(agentID)
	if err != nil {
		http.Error(w, "mint run key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	run := &Run{
		ID:       randomRunID(),
		Name:     req.Name,
		AgentID:  agentID,
		KeyID:    keyID,
		Key:      key,
		Owner:    resolveAgentID(r, ""),
		Allow:    allow,
		Deadline: time.Now().Add(ttl),
		Sock:     filepath.Join(runDir, "akasha.sock"),
		done:     make(chan struct{}),
	}

	// The run's own listener lives in the run directory, not ~/.akasha, so the
	// sandbox can deny the whole data directory with no hole punched in it.
	os.Remove(run.Sock)
	ln, err := net.Listen("unix", run.Sock)
	if err != nil {
		s.vlt.RevokeAgentKey(keyID)
		http.Error(w, "run socket: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// A unix socket is created 0777 &^ umask, so on a default umask any local
	// process can connect to it.
	if err := os.Chmod(run.Sock, 0o600); err != nil {
		ln.Close()
		os.Remove(run.Sock)
		s.vlt.RevokeAgentKey(keyID)
		http.Error(w, "run socket: cannot restrict "+run.Sock+" to this user: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	run.ln = ln

	s.runsMu.Lock()
	if s.runs == nil {
		s.runs = map[string]*Run{}
	}
	s.runs[run.ID] = run
	s.runsMu.Unlock()

	go s.serveRun(run)
	go s.reapRun(run)

	s.auditL.Emit(audit.Event{
		Action:         audit.ActionRunBegin,
		AgentID:        agentID,
		IdentitySource: policy.ServerAssigned.String(),
		ToolName:       "akasha_run",
		RunID:          run.ID,
		Task: fmt.Sprintf("supervised launch; grants: %s", func() string {
			if len(req.Assume) == 0 {
				return "(none)"
			}
			return strings.Join(req.Assume, ", ")
		}()),
	})

	jsonOK(w, beginRunResponse{RunID: run.ID, AgentID: agentID, Key: key, Socket: run.Sock})
}

// handleRunAttach is the control connection. The daemon holds it open and ends
// the run when it drops.
//
// This is the SIGKILL story, and it is strictly stronger than `akasha exec`'s
// 24h file TTL: kill the supervisor and the orphaned child's very next broker
// call gets a 401, rather than the credential staying usable until a sweeper
// notices.
func (s *Server) handleRunAttach(w http.ResponseWriter, r *http.Request) {
	run := s.lookupRun(r.URL.Query().Get("run_id"))
	if run == nil {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	if !ownsRun(r, run) {
		http.Error(w, foreignRunRefusal, http.StatusForbidden)
		return
	}
	s.runsMu.Lock()
	run.attached = true
	s.runsMu.Unlock()

	// Flush headers so the CLI knows the run is live.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"attached\":%q}\n", run.ID)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	select {
	case <-r.Context().Done(): // supervisor died or detached
	case <-run.done: // /run/end, or the deadline
	}
	s.endRun(run, "control connection closed")
}

func (s *Server) handleRunEnd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID string `json:"run_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if run := s.lookupRun(req.RunID); run != nil {
		if !ownsRun(r, run) {
			http.Error(w, foreignRunRefusal, http.StatusForbidden)
			return
		}
		s.endRun(run, "run ended")
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// foreignRunRefusal answers a caller reaching for a run it did not start.
//
// Ending a run revokes its key, so an unscoped /run/end is a kill switch any
// authenticated process could pull on any other run; attaching is worse, since
// the control connection decides when the run dies.
const foreignRunRefusal = "this run was started by another caller, and only its supervisor may attach to it " +
	"or end it — run `akasha run` yourself to get a run you control."

// ownsRun reports whether the verified caller is the identity that began run.
func ownsRun(r *http.Request, run *Run) bool {
	return run.Owner != "" && resolveAgentID(r, "") == run.Owner
}

func (s *Server) lookupRun(id string) *Run {
	if id == "" {
		return nil
	}
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	return s.runs[id]
}

// endRun revokes the run's key and closes its socket. Idempotent.
func (s *Server) endRun(run *Run, why string) {
	s.runsMu.Lock()
	_, live := s.runs[run.ID]
	delete(s.runs, run.ID)
	s.runsMu.Unlock()
	if !live {
		return
	}
	run.end()
	os.Remove(run.Sock)
	// Revoke rather than delete, so a key presented later reports "revoked"
	// instead of the misleading "run akasha agent resync".
	s.vlt.RevokeAgentKey(run.KeyID)
	s.auditL.Emit(audit.Event{
		Action:         audit.ActionRunEnd,
		AgentID:        run.AgentID,
		IdentitySource: policy.ServerAssigned.String(),
		ToolName:       "akasha_run",
		RunID:          run.ID,
		Task:           why,
	})
}

// reapRun enforces the deadline, and ends a run whose supervisor never attached
// (a CLI that died between /run/begin and /run/attach).
func (s *Server) reapRun(run *Run) {
	grace := time.NewTimer(5 * time.Second)
	defer grace.Stop()
	select {
	case <-run.done:
		return
	case <-grace.C:
		s.runsMu.Lock()
		attached := run.attached
		s.runsMu.Unlock()
		if !attached {
			s.endRun(run, "supervisor never attached")
			return
		}
	}
	select {
	case <-run.done:
	case <-time.After(time.Until(run.Deadline)):
		s.endRun(run, "run deadline reached")
	}
}

// serveRun serves the run's private socket.
func (s *Server) serveRun(run *Run) {
	hs := &http.Server{Handler: s.runSocketKeyOnly(run, s.mux)}
	go func() { <-run.done; hs.Close() }()
	hs.Serve(run.ln)
}

// runSocketKeyOnly makes Run.Key mean what its name says.
//
// The key was minted, handed to the launcher and then never compared to
// anything: only KeyID was used, for revocation. So the run's private socket —
// the one path the sandbox is allowed to reach — accepted ANY valid vault key,
// including the human CLI's, whose capabilities are unrestricted. A run
// directory is inside the sandbox; a key that leaks into it must not be usable,
// and the run's own key must be the only one that is.
//
// A keyless request is left to auth, so the caller gets the one refusal that
// explains where keys come from.
func (s *Server) runSocketKeyOnly(run *Run, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Akasha-Key")
		if key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(run.Key)) != 1 {
			http.Error(w, fmt.Sprintf("this socket belongs to run %q and accepts only that run's key — "+
				"present the AKASHA_AGENT_KEY the supervisor set, or talk to the daemon's own socket instead.",
				run.Name), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// runForKey returns the live run a verified identity IS, and whether that
// identity names a run the daemon no longer has.
//
// The lookup is by key as well as agent id because two concurrent runs may
// share a name, and therefore an identity: matching on the name alone could
// evaluate one run's request against the other's --assume grant.
func (s *Server) runForKey(agentID, key string) (*Run, bool) {
	if !strings.HasPrefix(agentID, vault.RunIdentityPrefix) {
		return nil, false
	}
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	for _, run := range s.runs {
		if run.AgentID == agentID && subtle.ConstantTimeCompare([]byte(run.Key), []byte(key)) == 1 {
			return run, false
		}
	}
	return nil, true
}

// runCapabilities is the profile that makes broker-only real. It reports false
// when the request has been refused and the caller must return.
//
// A run may resolve credentials it was launched with, and nothing else. This is
// enforced in the daemon rather than the CLI because the thing being
// constrained is a process that can talk to the socket itself, so a
// launcher-side check would be decoration.
//
// The profile is keyed on the run IDENTITY, and that is the whole point. It
// used to wrap only the handler served on the run's private socket, which made
// the constraint a property of the LISTENER: neither sandbox confines the
// network, so a sandboxed agent holding the run key opened a TCP connection to
// the daemon's loopback port and reached /retrieve, /assume and /grant with no
// profile applied at all. A capability that a `connect()` call escapes is not a
// capability.
//
// It is also strictly narrower than the policy file — a run can never do
// something policy forbids, only less.
func (s *Server) runCapabilities(w http.ResponseWriter, r *http.Request, run *Run) bool {
	// A run must not be able to mint another one: /run/begin takes its own
	// --assume list, so a run that could start a run would write itself a wider
	// grant than the human gave it. /run/attach and /run/end are the supervisor's
	// control connection, not the child's.
	if strings.HasPrefix(r.URL.Path, "/run/") {
		http.Error(w, "a supervised run may not start, join or end a run — its capabilities are fixed by the "+
			"`akasha run --assume` the human launched it with.", http.StatusForbidden)
		return false
	}
	switch r.URL.Path {
	case "/retrieve":
		http.Error(w, "a supervised run may not read raw secret values — it brokers them per "+
			"operation instead. Use the provider's credential helper.", http.StatusForbidden)
	case "/assume":
		http.Error(w, "a supervised run may not materialize credentials — it brokers them per "+
			"operation instead.", http.StatusForbidden)
	case "/credential/retrieve", "/label/list":
		http.Error(w, "a supervised run may not enumerate or read the vault inventory.", http.StatusForbidden)
	case "/grant":
		http.Error(w, "a supervised run may not delegate its authority to another agent.", http.StatusForbidden)
	case "/put", "/store", "/label/set", "/label/delete", "/profile/save", "/vault/purge":
		// The write side was open, and it is the more valuable half: a run that
		// can re-point aws:default at a credential of its choosing redirects
		// every later assume, git push and credential_process the human makes,
		// without ever reading a secret itself.
		//
		// /wrap is deliberately absent from this list. It mints a fresh token and
		// binds no name, so it cannot redirect anything — and it is the call an
		// SDK agent makes to keep a secret OUT of the model's context. Refusing it
		// would disable the protective path exactly inside the tier meant to be
		// the safest place to run.
		http.Error(w, "a supervised run may not write to the vault — it uses the credentials it was "+
			"launched with and cannot bind, store or delete any.", http.StatusForbidden)
	case "/resolve":
		provider := r.URL.Query().Get("provider")
		instance := r.URL.Query().Get("instance")
		if instance == "" {
			instance = "default"
		}
		if !run.Allow[provider+":"+instance] {
			http.Error(w, fmt.Sprintf("run %q was not launched with --assume %s:%s, so it may not use it",
				run.Name, provider, instance), http.StatusForbidden)
			return false
		}
		return true
	default:
		return true
	}
	return false
}

// staleRunRefusal answers a key whose run identity has no live run behind it.
//
// Such a key must never be served unprofiled: the capability profile hangs off
// the live run, so a run identity the daemon cannot resolve would otherwise get
// the full mux.
const staleRunRefusal = "this key belongs to a supervised run that is no longer live — the run ended, and its " +
	"credentials went with it. Start a new one with `akasha run`."

// runFrom returns the run the caller IS, if any.
func runFrom(r *http.Request) *Run {
	v, _ := r.Context().Value(ctxRun).(*Run)
	return v
}

// sweepRunKeys revokes leftover run:* keys at daemon start.
//
// A run cannot outlive the daemon, so any such key still active is a remnant of
// a daemon that exited without tearing its runs down.
func (s *Server) sweepRunKeys() {
	keys, err := s.vlt.ListAgentKeys()
	if err != nil {
		return
	}
	for _, k := range keys {
		if !k.Revoked && strings.HasPrefix(k.AgentID, "run:") {
			s.vlt.RevokeAgentKey(k.KeyID)
		}
	}
}

// randomRunID is unguessable on purpose: the id is the handle /run/end and
// /run/attach take, and a timestamp-and-pid one is derivable by anything that
// knows roughly when the run started.
func randomRunID() string { return rand.Text() }
