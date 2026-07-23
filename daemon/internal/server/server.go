package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/resolve"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

const HTTPPort = 7743

// WrapRequest is sent by SDK clients to classify and vault sensitive content.
type WrapRequest struct {
	AgentID  string `json:"agent_id"`
	ToolName string `json:"tool_name"`
	Content  string `json:"content"`
	// Reasoning provenance — captured at the moment of the tool call.
	Task           string `json:"task,omitempty"`
	ReasoningTrace string `json:"reasoning_trace,omitempty"`
	TriggeredBy    string `json:"triggered_by,omitempty"`
	RunID          string `json:"run_id,omitempty"`
}

type WrapResponse struct {
	CleanContent string `json:"clean_content"`
	Vaulted      bool   `json:"vaulted"`
	// Token/Category/Risk describe the highest-risk vaulted secret, for the
	// single-secret common case and backward compatibility. Tokens lists every
	// vaulted secret, in the order they appear in CleanContent.
	Token    string   `json:"token,omitempty"`
	Tokens   []string `json:"tokens,omitempty"`
	Category string   `json:"category,omitempty"`
	Risk     string   `json:"risk,omitempty"`
}

// RetrieveRequest supports both direct retrieval (token only) and
// grant-based cross-agent retrieval (grant_id from an A2A task payload).
type RetrieveRequest struct {
	Token          string `json:"token,omitempty"`
	GrantID        string `json:"grant_id,omitempty"`
	AgentID        string `json:"agent_id"`
	RequestingTool string `json:"requesting_tool"`
	Task           string `json:"task,omitempty"`
	ReasoningTrace string `json:"reasoning_trace,omitempty"`
	RunID          string `json:"run_id,omitempty"`
}

type RetrieveResponse struct {
	Value string `json:"value"`
}

// GrantRequest is sent by Agent A to delegate a vault token to Agent B.
type GrantRequest struct {
	Token        string `json:"token"`
	GrantorAgent string `json:"grantor_agent"`
	GranteeAgent string `json:"grantee_agent"`
	AllowedTool  string `json:"allowed_tool,omitempty"`
	Task         string `json:"task,omitempty"`
	TTLSeconds   int    `json:"ttl_seconds,omitempty"`
}

type GrantResponse struct {
	GrantID string `json:"grant_id"`
}

// StoreRequest vaults a value directly, bypassing classification.
// Used by trusted callers (e.g. akasha discover) that already know
// the content is sensitive.
type StoreRequest struct {
	AgentID  string `json:"agent_id"`
	ToolName string `json:"tool_name"`
	Content  string `json:"content"`
	Category string `json:"category"`
	Risk     string `json:"risk"`
	Task     string `json:"task,omitempty"`
	RunID    string `json:"run_id,omitempty"`
}

type StoreResponse struct {
	Token string `json:"token"`
}

type Server struct {
	clf         *classifier.Classifier
	vlt         *vault.Vault
	auditL      *audit.Logger
	policy      *policy.Engine
	mux         *http.ServeMux
	mu          sync.Mutex
	httpServers []*http.Server
}

func New(clf *classifier.Classifier, vlt *vault.Vault, auditL *audit.Logger) *Server {
	s := &Server{clf: clf, vlt: vlt, auditL: auditL,
		policy: policy.NewEngine(policy.DefaultPath()), mux: http.NewServeMux()}
	s.mux.HandleFunc("/wrap", s.auth(s.handleWrap))
	s.mux.HandleFunc("/store", s.auth(s.handleStore))
	s.mux.HandleFunc("/retrieve", s.auth(s.handleRetrieve))
	s.mux.HandleFunc("/grant", s.auth(s.handleGrant))
	s.mux.HandleFunc("/inspect", s.auth(s.handleInspect))
	s.mux.HandleFunc("/label/set", s.auth(s.handleLabelSet))
	s.mux.HandleFunc("/label/get", s.auth(s.handleLabelGet))
	s.mux.HandleFunc("/label/list", s.auth(s.handleLabelList))
	s.mux.HandleFunc("/profile/save", s.auth(s.handleProfileSave))
	s.mux.HandleFunc("/vault/purge", s.auth(s.handleVaultPurge))
	s.mux.HandleFunc("/put", s.auth(s.handlePut))
	s.mux.HandleFunc("/assume", s.auth(s.handleAssume))
	s.mux.HandleFunc("/resolve", s.auth(s.handleResolve))
	s.mux.HandleFunc("/health", s.handleHealth) // health is unauthenticated
	return s
}

// verifiedAgentKey is the context key for the verified agent ID.
type ctxKey string

const ctxAgentID ctxKey = "agent_id"

// auth is middleware that checks X-Akasha-Key when present.
// - No key: request passes through, agent_id comes from request body (advisory).
// - Valid key: verified agent_id injected into context, overrides body.
// - Invalid key: 401 rejected.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Akasha-Key")
		if key != "" {
			agentID, err := s.vlt.VerifyAgentKey(key)
			if err != nil {
				msg := "agent key not recognised by the vault (likely after a vault rebuild) — run `akasha agent resync` to re-authorize this key, then retry. No restart needed."
				if errors.Is(err, vault.ErrAgentKeyRevoked) {
					msg = "agent key has been revoked — if this was not intended, issue a new one with `akasha agent resync --rotate`"
				}
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}
			// Inject verified identity into context — handlers read this
			// and it wins over whatever agent_id is in the request body.
			ctx := context.WithValue(r.Context(), ctxAgentID, agentID)
			r = r.WithContext(ctx)
		}
		next(w, r)
	}
}

// resolveAgentID returns the verified agent_id from context (if key was
// presented) or falls back to the self-reported value from the request body.
func resolveAgentID(r *http.Request, bodyAgentID string) string {
	if v, ok := r.Context().Value(ctxAgentID).(string); ok && v != "" {
		return v
	}
	return bodyAgentID
}

// Handler exposes the mux for testing (httptest) and embedding.
func (s *Server) Handler() http.Handler { return s.mux }

// SetPolicyEngine replaces the policy engine (tests, custom policy paths).
func (s *Server) SetPolicyEngine(e *policy.Engine) { s.policy = e }

// authorize evaluates the request against ~/.akasha/policy.yaml, resolving
// "ask" rules interactively. On denial it emits a DENIED audit event and
// writes the 403; the caller must return immediately when it reports false.
func (s *Server) authorize(w http.ResponseWriter, req policy.Request) bool {
	err := s.policy.Authorize(req)
	if err == nil {
		return true
	}
	s.auditL.Emit(audit.Event{
		Token:    req.Token,
		Action:   audit.ActionDenied,
		Category: req.Category,
		Risk:     req.Risk,
		AgentID:  req.AgentID,
		ToolName: req.Tool,
		Task:     err.Error(),
	})
	http.Error(w, err.Error(), http.StatusForbidden)
	return false
}

// serve runs a tracked *http.Server on ln so it can be gracefully stopped via
// Shutdown. Returns nil on a clean shutdown.
func (s *Server) serve(ln net.Listener, h http.Handler) error {
	hs := &http.Server{Handler: h}
	s.mu.Lock()
	s.httpServers = append(s.httpServers, hs)
	s.mu.Unlock()
	if err := hs.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ListenUnix starts the Unix socket listener (primary, fastest path).
func (s *Server) ListenUnix(socketPath string) error {
	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("unix socket: %w", err)
	}
	log.Printf("akasha: listening on unix socket %s", socketPath)
	// The Unix socket is unreachable from a browser, so it is served without the
	// host guard — clients set their own Host values over it (e.g. the SDK's
	// "akasha").
	return s.serve(ln, s.mux)
}

// ListenHTTP starts the HTTP fallback listener on the default port.
func (s *Server) ListenHTTP() error {
	return s.listenTCP(fmt.Sprintf("127.0.0.1:%d", HTTPPort))
}

// listenTCP binds addr and serves; split out so tests can use an ephemeral port.
func (s *Server) listenTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("akasha: listening on http %s", ln.Addr())
	// The TCP listener is the only surface a web page can reach, so it is wrapped
	// in the DNS-rebinding / cross-origin guard.
	return s.serve(ln, hostGuard(s.mux))
}

// hostGuard is the drive-by defence for the always-on TCP loopback listener. A
// web page the user visits can send requests to a loopback port, so we require
// the request Host to name the local machine — a DNS-rebinding attack arrives as
// `Host: attacker.example` after the attacker's domain re-resolves to 127.0.0.1
// — and we refuse any request carrying a non-loopback Origin (a cross-origin
// browser fetch/POST). Non-browser local clients (CLI, SDK, agents) set a
// loopback Host and send no Origin, so they are unaffected. Browsers cannot open
// the Unix socket, so only the TCP handler is wrapped.
func hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "refused: request Host is not loopback (possible DNS rebinding)", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !loopbackOrigin(o) {
			http.Error(w, "refused: cross-origin request", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loopbackHost reports whether an HTTP Host header names the local machine —
// 127.0.0.0/8, ::1, or "localhost" — with or without a port.
func loopbackHost(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// loopbackOrigin reports whether an Origin header's URL names a loopback host.
func loopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return loopbackHost(u.Host)
}

// riskRank orders the classifier's risk levels so the wrap response can report
// the highest-risk secret among several. Unknown/empty risk ranks lowest.
func riskRank(risk string) int {
	switch strings.ToLower(risk) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Shutdown gracefully stops every listener started via Listen*.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	servers := append([]*http.Server(nil), s.httpServers...)
	s.mu.Unlock()
	for _, hs := range servers {
		hs.Shutdown(ctx)
	}
}

func (s *Server) handleWrap(w http.ResponseWriter, r *http.Request) {
	var req WrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	agentID := resolveAgentID(r, req.AgentID)

	// ClassifyAll (not Classify) so EVERY secret in the payload is caught — a
	// multi-secret payload must not leave any value unredacted in the content
	// returned to the model.
	results := s.clf.ClassifyAll(req.ToolName, req.Content)
	if len(results) == 0 {
		jsonOK(w, WrapResponse{CleanContent: req.Content, Vaulted: false})
		return
	}

	// Redact longest value first so a secret that contains another (e.g. a URL
	// embedding its password) is replaced before its substring. Empty-value
	// results (a risky tool-name signal) sort last and are handled below.
	sort.SliceStable(results, func(i, j int) bool {
		return len(results[i].Value) > len(results[j].Value)
	})

	auditVault := func(token, category, risk string) {
		s.auditL.Emit(audit.Event{
			RunID:          req.RunID,
			Token:          token,
			Action:         audit.ActionVaulted,
			Category:       category,
			Risk:           risk,
			AgentID:        agentID,
			ToolName:       req.ToolName,
			Task:           req.Task,
			ReasoningTrace: req.ReasoningTrace,
			TriggeredBy:    req.TriggeredBy,
		})
	}

	clean := req.Content
	var tokens []string
	seen := map[string]bool{}
	repToken, repCategory, repRisk := "", "", ""
	for _, res := range results {
		if res.Value == "" || seen[res.Value] {
			continue // risky-tool signal, or a value already vaulted
		}
		seen[res.Value] = true
		token, err := s.vlt.Store(res.Value, res.Category, res.Risk, agentID, req.ToolName, 0)
		if err != nil {
			http.Error(w, "vault error", http.StatusInternalServerError)
			return
		}
		clean = strings.ReplaceAll(clean, res.Value, token)
		tokens = append(tokens, token)
		auditVault(token, res.Category, res.Risk)
		if repToken == "" || riskRank(res.Risk) > riskRank(repRisk) {
			repToken, repCategory, repRisk = token, res.Category, res.Risk
		}
	}

	// Risky tool-name with no concrete value to redact: vault the whole payload
	// as a record and return it unchanged (prior behavior).
	if len(tokens) == 0 {
		token, err := s.vlt.Store(req.Content, results[0].Category, results[0].Risk, agentID, req.ToolName, 0)
		if err != nil {
			http.Error(w, "vault error", http.StatusInternalServerError)
			return
		}
		auditVault(token, results[0].Category, results[0].Risk)
		jsonOK(w, WrapResponse{
			CleanContent: req.Content, Vaulted: true, Token: token, Tokens: []string{token},
			Category: results[0].Category, Risk: results[0].Risk,
		})
		return
	}

	jsonOK(w, WrapResponse{
		CleanContent: clean,
		Vaulted:      true,
		Token:        repToken,
		Tokens:       tokens,
		Category:     repCategory,
		Risk:         repRisk,
	})
}

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		http.Error(w, "content required", http.StatusBadRequest)
		return
	}
	agentID := resolveAgentID(r, req.AgentID)
	if req.Category == "" {
		req.Category = "Unknown"
	}
	if req.Risk == "" {
		req.Risk = "high"
	}

	token, err := s.vlt.Store(req.Content, req.Category, req.Risk, agentID, req.ToolName, 0)
	if err != nil {
		http.Error(w, "vault error", http.StatusInternalServerError)
		return
	}

	s.auditL.Emit(audit.Event{
		RunID:    req.RunID,
		Token:    token,
		Action:   audit.ActionVaulted,
		Category: req.Category,
		Risk:     req.Risk,
		AgentID:  agentID,
		ToolName: req.ToolName,
		Task:     req.Task,
	})

	jsonOK(w, StoreResponse{Token: token})
}

func (s *Server) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	var req RetrieveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	agentID := resolveAgentID(r, req.AgentID)
	token := req.Token

	// Policy gate. Evaluated before touching the vault — and in the grant
	// case before redemption, so a policy denial never burns a single-use
	// grant. Entry metadata (category/risk) is looked up best-effort; an
	// unknown token simply evaluates with empty category/risk and fails
	// naturally at retrieval below.
	polToken := token
	if req.GrantID != "" {
		if g, err := s.vlt.InspectGrant(req.GrantID); err == nil {
			polToken = g.Token
		}
	}
	polReq := policy.Request{
		Action:  "retrieve",
		AgentID: agentID,
		Tool:    req.RequestingTool,
		Token:   polToken,
		Task:    req.Task,
	}
	if entry, err := s.vlt.Inspect(polToken); err == nil {
		polReq.Category = entry.Category
		polReq.Risk = entry.Risk
	}
	if !s.authorize(w, polReq) {
		return
	}

	// Grant-based retrieval path (A2A cross-agent delegation). Redeeming claims
	// the single-use grant atomically; the value is fetched (and audited) below,
	// on the same path as a direct retrieval, so the audit reflects what was
	// actually delivered rather than the intent to deliver.
	if req.GrantID != "" {
		grantToken, err := s.vlt.RedeemGrant(req.GrantID, agentID, req.RequestingTool)
		if err != nil {
			s.auditL.Emit(audit.Event{
				GrantID: req.GrantID,
				AgentID: agentID,
				Action:  audit.ActionDenied,
			})
			http.Error(w, "grant denied: "+err.Error(), http.StatusForbidden)
			return
		}
		token = grantToken
	}

	if token == "" {
		http.Error(w, "token or grant_id required", http.StatusBadRequest)
		return
	}

	value, err := s.vlt.Retrieve(token, req.RequestingTool)
	if err != nil {
		s.auditL.Emit(audit.Event{
			GrantID:  req.GrantID,
			Token:    token,
			AgentID:  agentID,
			Action:   audit.ActionDenied,
			ToolName: req.RequestingTool,
		})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	s.auditL.Emit(audit.Event{
		RunID:          req.RunID,
		GrantID:        req.GrantID,
		Token:          token,
		Action:         audit.ActionRetrieved,
		AgentID:        agentID,
		ToolName:       req.RequestingTool,
		Task:           req.Task,
		ReasoningTrace: req.ReasoningTrace,
	})

	jsonOK(w, RetrieveResponse{Value: value})
}

func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	var req GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	polReq := policy.Request{
		Action:  "grant",
		AgentID: resolveAgentID(r, req.GrantorAgent),
		Tool:    req.AllowedTool,
		Token:   req.Token,
		Task:    req.Task,
	}
	if entry, err := s.vlt.Inspect(req.Token); err == nil {
		polReq.Category = entry.Category
		polReq.Risk = entry.Risk
	}
	if !s.authorize(w, polReq) {
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	grantID, err := s.vlt.CreateGrant(req.Token, req.GrantorAgent, req.GranteeAgent, req.AllowedTool, req.Task, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.auditL.Emit(audit.Event{
		Token:   req.Token,
		GrantID: grantID,
		Action:  audit.ActionGranted,
		AgentID: req.GrantorAgent,
		Task:    req.Task,
	})

	jsonOK(w, GrantResponse{GrantID: grantID})
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	// Inspecting a token/grant exposes its category, risk, owning agent, and
	// timestamps — metadata about a secret — so it passes the policy gate too.
	if !s.authorize(w, policy.Request{Action: "inspect", AgentID: resolveAgentID(r, "akasha-inspect"), Tool: "akasha_inspect"}) {
		return
	}
	token := r.URL.Query().Get("token")
	grantID := r.URL.Query().Get("grant_id")

	if grantID != "" {
		g, err := s.vlt.InspectGrant(grantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, g)
		return
	}

	if token == "" {
		http.Error(w, "token or grant_id required", http.StatusBadRequest)
		return
	}

	entry, err := s.vlt.Inspect(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.auditL.Emit(audit.Event{
		Token:  token,
		Action: audit.ActionInspected,
	})

	jsonOK(w, entry)
}

func (s *Server) handleProfileSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string            `json:"provider"`
		Profile  string            `json:"profile"`
		Token    string            `json:"token"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.Provider == "" || req.Profile == "" || req.Token == "" {
		http.Error(w, "provider, profile, and token required", http.StatusBadRequest)
		return
	}
	if err := s.vlt.SaveProfile(req.Provider, req.Profile, req.Token, req.Metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// handleVaultPurge garbage-collects orphaned discovery credential chains left
// behind by repeated `akasha setup` / `akasha discover` runs.
func (s *Server) handleVaultPurge(w http.ResponseWriter, r *http.Request) {
	n, err := s.vlt.PurgeOrphans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int{"purged": n})
}

func (s *Server) handleLabelSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Token == "" {
		http.Error(w, "name and token required", http.StatusBadRequest)
		return
	}
	if err := s.vlt.SetLabel(req.Name, req.Token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleLabelGet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	// Policy gate: label/get hands back the raw value, so it is the same
	// operation as an assume — without this it would be a bypass around the
	// /retrieve and /assume gates.
	agentID := resolveAgentID(r, "akasha-assume")
	provider, instance := name, ""
	if i := strings.Index(name, ":"); i > 0 {
		provider, instance = name[:i], name[i+1:]
	}
	if !s.authorize(w, policy.Request{
		Action:   "assume",
		AgentID:  agentID,
		Tool:     "akasha_assume",
		Provider: provider,
		Instance: instance,
		Category: "Credential",
		Risk:     "critical",
	}) {
		return
	}

	token, err := s.vlt.GetLabel(name)
	if err != nil {
		msg := err.Error()
		// A label is "<provider>:<instance>" — on a miss, tell the caller
		// which instances WOULD resolve, so a typo'd name is self-correcting.
		if i := strings.Index(name, ":"); i > 0 {
			msg = fmt.Sprintf("%s — %s", msg, s.availableHint(name[:i]))
		}
		http.Error(w, msg, http.StatusNotFound)
		return
	}
	value, err := s.vlt.Retrieve(token, "akasha_assume")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditL.Emit(audit.Event{
		Token:    token,
		Action:   audit.ActionRetrieved,
		AgentID:  "akasha-assume",
		ToolName: "akasha_assume",
		Task:     fmt.Sprintf("Assume label %q", name),
	})
	jsonOK(w, map[string]string{"value": value})
}

// availableHint lists the vaulted instances for a provider, so a failed
// lookup tells the caller (often an agent that guessed or typo'd a profile)
// what would resolve. Instance names are not secrets — only their values are.
func (s *Server) availableHint(provider string) string {
	labels, err := s.vlt.ListLabels(provider + ":")
	if err != nil || len(labels) == 0 {
		return fmt.Sprintf("nothing is vaulted for provider %q (run `akasha discover %s` or `akasha put %s:<name>`)",
			provider, provider, provider)
	}
	for i, l := range labels {
		labels[i] = strings.TrimPrefix(l, provider+":")
	}
	return fmt.Sprintf("available %s instances: %s", provider, strings.Join(labels, ", "))
}

func (s *Server) handleLabelList(w http.ResponseWriter, r *http.Request) {
	// The label list is the provider:instance inventory of what is vaulted, so it
	// passes the policy gate rather than being readable by any caller.
	if !s.authorize(w, policy.Request{Action: "list", AgentID: resolveAgentID(r, "akasha-list"), Tool: "akasha_list"}) {
		return
	}
	prefix := r.URL.Query().Get("prefix")
	names, err := s.vlt.ListLabels(prefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, names)
}

// PutRequest stores a labelled credential map in one call — the simple way to
// vault a secret that discovery didn't find, so `assume` can use it later.
type PutRequest struct {
	Label  string            `json:"label"`            // e.g. "env:stripe"
	Fields map[string]string `json:"fields"`           // field → secret value
	Provider string          `json:"provider,omitempty"` // optional, for a profile row
	Profile  string          `json:"profile,omitempty"`
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	var req PutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Label == "" || len(req.Fields) == 0 {
		http.Error(w, "label and at least one field required", http.StatusBadRequest)
		return
	}
	agentID := resolveAgentID(r, "akasha-put")

	// Vault each field, then a {field: token} map the label points at.
	resolved := make(map[string]string, len(req.Fields))
	for field, value := range req.Fields {
		tok, err := s.vlt.Store(value, "UserSecret", "high", agentID, "akasha_put", 0)
		if err != nil {
			http.Error(w, "vault error", http.StatusInternalServerError)
			return
		}
		resolved[field] = tok
	}
	mapJSON, _ := json.Marshal(resolved)
	mapTok, err := s.vlt.Store(string(mapJSON), "CredentialMap", "high", agentID, "akasha_put", 0)
	if err != nil {
		http.Error(w, "vault error", http.StatusInternalServerError)
		return
	}
	if err := s.vlt.SetLabel(req.Label, mapTok); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Provider != "" && req.Profile != "" {
		s.vlt.SaveProfile(req.Provider, req.Profile, mapTok, nil)
	}

	s.auditL.Emit(audit.Event{
		Token:    mapTok,
		Action:   audit.ActionVaulted,
		Category: "UserSecret",
		Risk:     "high",
		AgentID:  agentID,
		ToolName: "akasha_put",
		Task:     fmt.Sprintf("Stored secret under label %q", req.Label),
	})
	jsonOK(w, map[string]string{"label": req.Label, "token": mapTok})
}

// handleAssume materializes a vaulted credential set into a short-lived
// provider-native file and returns env vars to set. The agent never receives
// the raw secret — only a handle. Every assume is audited.
func (s *Server) handleAssume(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider       string `json:"provider"`
		Profile        string `json:"profile"`
		TTLSeconds     int    `json:"ttl_seconds,omitempty"`
		AllowSecretEnv bool   `json:"allow_secret_env,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Provider == "" || req.Profile == "" {
		http.Error(w, "provider and profile required", http.StatusBadRequest)
		return
	}

	tpl := template.Get(req.Provider)

	// Refuse to hand back a raw secret as an env var value: that would land the
	// credential in the caller's context, defeating assume's "use it without
	// seeing it" contract. This covers providers whose env delivery materializes
	// a secret field (github/git's GITHUB_TOKEN, a source-brokered token) and the
	// generic env: provider (tpl == nil, always raw). File-delivered providers
	// (aws/ssh) set env vars to a file PATH and are unaffected. Only the trusted
	// human CLI opts in via allow_secret_env; the MCP agent tool strips it, so an
	// agent never receives the raw value.
	if !req.AllowSecretEnv && (tpl == nil || tpl.DeliversSecretEnv()) {
		http.Error(w, fmt.Sprintf("assume refuses to return %q as a raw secret in an environment variable — it would be exposed in your context. Use the credential helper (e.g. git brokers per-operation via `akasha helper %s` in a session configured by `akasha setup`), or vault_retrieve if you explicitly need the value.", req.Provider, req.Provider), http.StatusForbidden)
		return
	}

	agentID := resolveAgentID(r, "akasha-assume")

	resolved, err := s.credsFor(r.Context(), req.Provider, req.Profile, agentID, "akasha_assume")
	if err != nil {
		http.Error(w, err.Error(), credsErrStatus(err))
		return
	}

	// A new provider template must be trusted before Akasha applies it: delivery
	// writes a credential file and/or sets environment variables (which can
	// execute code) into the agent's session. Trust is explicit and hash-bound,
	// so an edited or freshly-dropped template is refused until re-approved; once
	// trusted it applies passively. Inert templates carry no sensitive
	// capability, so Approved passes them through untouched.
	if tpl != nil {
		store, terr := trust.Load()
		if terr != nil {
			http.Error(w, terr.Error(), http.StatusInternalServerError)
			return
		}
		if ok, _ := store.Approved(tpl); !ok {
			http.Error(w, fmt.Sprintf("template %q is not trusted yet — review it with `akasha template explain %s`, then approve once with `akasha template trust %s`", req.Provider, req.Provider, req.Provider), http.StatusForbidden)
			return
		}
	}

	result, err := assume.Write(req.Provider, req.Profile, resolved,
		time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, result)
}

// handleResolve returns the resolved credential field map for provider:instance
// — brokered from the source backend if the template has one, else read from
// the vault. The `helper` command (credential_process / git helper) calls this
// so a source-backed provider is fetched live on every use and never stored.
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	instance := r.URL.Query().Get("instance")
	if provider == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}
	if instance == "" {
		instance = "default"
	}
	agentID := resolveAgentID(r, "akasha-helper")
	creds, err := s.credsFor(r.Context(), provider, instance, agentID, "akasha_helper")
	if err != nil {
		http.Error(w, err.Error(), credsErrStatus(err))
		return
	}
	jsonOK(w, map[string]interface{}{"fields": creds})
}

// credsFor returns the field→value credential map for provider:instance. When
// the provider template declares a source block it BROKERS the secret from that
// backend (1Password, Vault, …) — trust-gated and audited, never stored;
// otherwise it reads the vaulted label. This is the single point both the
// assume and helper paths flow through, so brokering applies to both.
func (s *Server) credsFor(ctx context.Context, provider, instance, agentID, tool string) (map[string]string, error) {
	// Policy gate. An assume hands the agent's tools a full working
	// credential, so the request is evaluated as critical-risk regardless of
	// how the underlying entries were classified.
	if err := s.policy.Authorize(policy.Request{
		Action:   "assume",
		AgentID:  agentID,
		Tool:     tool,
		Provider: provider,
		Instance: instance,
		Category: "Credential",
		Risk:     "critical",
	}); err != nil {
		s.auditL.Emit(audit.Event{
			Action:   audit.ActionDenied,
			Category: "Credential",
			Risk:     "critical",
			AgentID:  agentID,
			ToolName: tool,
			Task:     err.Error(),
		})
		return nil, &statusError{http.StatusForbidden, err}
	}

	if tpl := template.Get(provider); tpl != nil && len(tpl.Source) > 0 {
		store, err := trust.Load()
		if err != nil {
			return nil, &statusError{http.StatusInternalServerError, err}
		}
		creds, err := resolve.ResolveTemplate(ctx, store, tpl, 0, instance)
		if err != nil {
			st := http.StatusBadRequest
			if strings.Contains(err.Error(), "not trusted") {
				st = http.StatusForbidden // untrusted source → refuse to run the backend
			}
			return nil, &statusError{st, err}
		}
		s.auditL.Emit(audit.Event{
			Action:   audit.ActionRetrieved,
			AgentID:  agentID,
			ToolName: tool,
			Task:     fmt.Sprintf("Brokered %s:%s from %s backend (on-demand, not stored)", provider, instance, tpl.Source[0].Backend),
		})
		return creds, nil
	}

	// Vault path: label "aws:default" → credential-map token → field tokens.
	label := provider + ":" + instance
	mapToken, err := s.vlt.GetLabel(label)
	if err != nil {
		return nil, &statusError{http.StatusNotFound, fmt.Errorf("no vaulted credentials for %q — %s", label, s.availableHint(provider))}
	}
	mapJSON, err := s.vlt.Retrieve(mapToken, tool)
	if err != nil {
		return nil, &statusError{http.StatusInternalServerError, err}
	}
	tokenMap, err := assume.ParseCredMap(mapJSON)
	if err != nil {
		return nil, &statusError{http.StatusInternalServerError, fmt.Errorf("corrupt credential map")}
	}
	resolved := make(map[string]string, len(tokenMap))
	for field, tok := range tokenMap {
		val, err := s.vlt.Retrieve(tok, tool)
		if err != nil {
			return nil, &statusError{http.StatusInternalServerError, fmt.Errorf("retrieve %s: %w", field, err)}
		}
		resolved[field] = val
	}
	s.auditL.Emit(audit.Event{
		Token:    mapToken,
		Action:   audit.ActionRetrieved,
		AgentID:  agentID,
		ToolName: tool,
		Task:     fmt.Sprintf("Assume %s:%s", provider, instance),
	})
	return resolved, nil
}

// statusError carries the HTTP status a credsFor failure should map to.
type statusError struct {
	status int
	err    error
}

func (e *statusError) Error() string { return e.err.Error() }

// credsErrStatus extracts the intended HTTP status, defaulting to 400.
func credsErrStatus(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return se.status
	}
	return http.StatusBadRequest
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	total, expired, _ := s.vlt.Stats()
	jsonOK(w, map[string]interface{}{
		"status":        "ok",
		"vault_total":   total,
		"vault_expired": expired,
		"time":          time.Now().UTC(),
	})
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
