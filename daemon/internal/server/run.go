package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
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
	Key     string // minted plaintext; returned once, held to authenticate the run socket

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
	// a name it chose. Note honestly that this is the same advisory "no key =
	// the human" signal disclosed in THREATMODEL — an agent defeats it by
	// unsetting AKASHA_AGENT_KEY. It is drift protection, not an authorization
	// check, and is documented as such.
	if isVerifiedAgent(r) {
		http.Error(w, "akasha run must be started by you, not by an agent (this request presented an "+
			"agent key). If you are the human, unset AKASHA_AGENT_KEY and retry.", http.StatusForbidden)
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
	if req.RunDir == "" || !filepath.IsAbs(req.RunDir) {
		http.Error(w, "run_dir must be an absolute path", http.StatusBadRequest)
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

	agentID := "run:" + req.Name
	keyID, key, err := s.vlt.CreateAgentKey(agentID)
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
		Allow:    allow,
		Deadline: time.Now().Add(ttl),
		Sock:     filepath.Join(req.RunDir, "akasha.sock"),
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
		s.endRun(run, "run ended")
	}
	jsonOK(w, map[string]string{"status": "ok"})
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
	hs := &http.Server{Handler: s.runCapabilities(run, s.mux)}
	go func() { <-run.done; hs.Close() }()
	hs.Serve(run.ln)
}

// runCapabilities is the profile that makes broker-only real.
//
// A run may resolve credentials it was launched with, and nothing else. This is
// deliberately enforced here rather than in the CLI: the thing being constrained
// is a process that can talk to the socket directly, so a launcher-side check
// would be decoration.
//
// It is also strictly narrower than the policy file — a run can never do
// something policy forbids, only less.
func (s *Server) runCapabilities(run *Run, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/retrieve":
			http.Error(w, "a supervised run may not read raw secret values — it brokers them per "+
				"operation instead. Use the provider's credential helper.", http.StatusForbidden)
			return
		case "/assume":
			http.Error(w, "a supervised run may not materialize credentials — it brokers them per "+
				"operation instead.", http.StatusForbidden)
			return
		case "/label/get", "/label/list":
			http.Error(w, "a supervised run may not enumerate or read the vault inventory.", http.StatusForbidden)
			return
		case "/grant":
			http.Error(w, "a supervised run may not delegate its authority to another agent.", http.StatusForbidden)
			return
		case "/resolve":
			provider := r.URL.Query().Get("provider")
			instance := r.URL.Query().Get("instance")
			if instance == "" {
				instance = "default"
			}
			if !run.Allow[provider+":"+instance] {
				http.Error(w, fmt.Sprintf("run %q was not launched with --assume %s:%s, so it may not use it",
					run.Name, provider, instance), http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxRun, run)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// runFrom returns the run a request arrived on, if any.
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

func randomRunID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}
