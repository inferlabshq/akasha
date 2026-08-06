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

	runsMu sync.Mutex
	runs   map[string]*Run
}

func New(clf *classifier.Classifier, vlt *vault.Vault, auditL *audit.Logger) *Server {
	s := &Server{clf: clf, vlt: vlt, auditL: auditL,
		policy: policy.NewEngine(policy.DefaultPath()), mux: http.NewServeMux()}

	// Give the engine somewhere durable to record that a policy was installed,
	// so a deleted policy.yaml fails closed instead of silently reverting to
	// allow-all, and a way to say so in the audit log — the policy file could
	// previously be edited, broken or removed without leaving a trace.
	s.policy.SetStateStore(vlt)
	s.policy.SetNotifier(s.policyNotifier())
	// Every route pins its HTTP method. Without this, a state-changing endpoint
	// answered ANY verb — so `<img src="http://127.0.0.1:7743/vault/purge">` on
	// a web page reached it: a subresource GET carries a loopback Host and no
	// Origin, which is exactly what hostGuard lets through.
	s.mux.HandleFunc("/wrap", post(s.auth(s.handleWrap)))
	s.mux.HandleFunc("/store", post(s.auth(s.handleStore)))
	s.mux.HandleFunc("/retrieve", post(s.auth(s.handleRetrieve)))
	s.mux.HandleFunc("/grant", post(s.auth(s.handleGrant)))
	s.mux.HandleFunc("/inspect", get(s.auth(s.handleInspect)))
	s.mux.HandleFunc("/label/set", post(s.auth(s.handleLabelSet)))
	s.mux.HandleFunc("/label/get", get(s.auth(s.handleLabelGet)))
	s.mux.HandleFunc("/label/list", get(s.auth(s.handleLabelList)))
	s.mux.HandleFunc("/profile/save", post(s.auth(s.handleProfileSave)))
	s.mux.HandleFunc("/vault/purge", post(s.auth(s.handleVaultPurge)))
	s.mux.HandleFunc("/put", post(s.auth(s.handlePut)))
	s.mux.HandleFunc("/assume", post(s.auth(s.handleAssume)))
	s.mux.HandleFunc("/resolve", get(s.auth(s.handleResolve)))
	s.mux.HandleFunc("/run/begin", post(s.auth(s.handleRunBegin)))
	s.mux.HandleFunc("/run/attach", get(s.auth(s.handleRunAttach)))
	s.mux.HandleFunc("/run/end", post(s.auth(s.handleRunEnd)))
	s.mux.HandleFunc("/health", get(s.handleHealth)) // health is unauthenticated

	// A run cannot outlive the daemon, so any still-active run:* key is a
	// remnant of a daemon that exited without tearing its runs down.
	s.sweepRunKeys()
	return s
}

// post and get restrict a handler to one HTTP method, answering anything else
// with 405. Read endpoints also accept HEAD, which net/http serves by running
// the handler and discarding the body.
func post(h http.HandlerFunc) http.HandlerFunc { return methodOnly(h, http.MethodPost) }
func get(h http.HandlerFunc) http.HandlerFunc {
	return methodOnly(h, http.MethodGet, http.MethodHead)
}

func methodOnly(h http.HandlerFunc, allowed ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, m := range allowed {
			if r.Method == m {
				h(w, r)
				return
			}
		}
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

// caller is who made a request, carrying the provenance of each identity field
// so the policy engine can tell a fact from a claim.
type caller struct {
	agentID  string
	agentSrc policy.Provenance
	tool     string
	toolSrc  policy.Provenance
	// sandboxed is set when the request arrived on a supervised run's private
	// socket — established by which listener accepted it, not by the caller.
	sandboxed bool
}

// policyReq seeds a policy.Request with this caller's identity.
func (c caller) policyReq(action string) policy.Request {
	return policy.Request{
		Action:      action,
		AgentID:     c.agentID,
		AgentSource: c.agentSrc,
		Tool:        c.tool,
		ToolSource:  c.toolSrc,
		Sandboxed:   c.sandboxed,
	}
}

// callerFromBody builds the identity for an endpoint where the CALLER names
// itself — /wrap, /store, /retrieve, /grant. A verified key wins; otherwise the
// body values are marked Asserted, so no allow rule can be satisfied by them.
func callerFromBody(r *http.Request, bodyAgentID, bodyTool string) caller {
	c := caller{agentID: bodyAgentID, agentSrc: policy.Asserted, tool: bodyTool, toolSrc: policy.Asserted,
		sandboxed: runFrom(r) != nil}
	if v, ok := r.Context().Value(ctxAgentID).(string); ok && v != "" {
		c.agentID, c.agentSrc = v, policy.Verified
	}
	return c
}

// callerForEndpoint builds the identity for an endpoint where the DAEMON names
// the caller — akasha-helper on /resolve, akasha-list on /label/list, and so
// on. The request body is never consulted, so these literals are not forgeable
// and rules written against them may grant.
//
// Splitting this from callerFromBody is the whole point: they used to be one
// function whose second parameter meant "body value" at four call sites and
// "daemon-chosen literal" at eight, which made the trust level of an identity
// invisible at the point of use.
func callerForEndpoint(r *http.Request, literalAgent, literalTool string) caller {
	c := caller{agentID: literalAgent, agentSrc: policy.ServerAssigned, tool: literalTool, toolSrc: policy.ServerAssigned,
		sandboxed: runFrom(r) != nil}
	if v, ok := r.Context().Value(ctxAgentID).(string); ok && v != "" {
		c.agentID, c.agentSrc = v, policy.Verified
	}
	return c
}

// resolveAgentID reports the effective agent id without its provenance, for
// audit records and error text where only the name matters.
func resolveAgentID(r *http.Request, fallback string) string {
	if v, ok := r.Context().Value(ctxAgentID).(string); ok && v != "" {
		return v
	}
	return fallback
}

// isVerifiedAgent reports whether the request presented a valid agent key — the
// auth middleware injects a verified agent_id into the context only then. A
// keyless caller (the human CLI, advisory identity) returns false.
func isVerifiedAgent(r *http.Request) bool {
	v, ok := r.Context().Value(ctxAgentID).(string)
	return ok && v != ""
}

// reservedToolPrefix namespaces the tool identities the daemon assigns itself
// when it knows which internal path is running — akasha_helper (the broker),
// akasha_assume, akasha_list, and friends. Those names are server-derived
// facts, and policy rules are written against them.
const reservedToolPrefix = "akasha_"

// checkCallerTool rejects a caller-supplied tool name that squats the reserved
// namespace.
//
// This closes a bypass of the whole USE-vs-READ model: `requesting_tool` is a
// free-text request-body field, and the shipped policy permitted
// `tool: akasha_helper` so the credential broker could function. Any caller
// that simply wrote that string into the body therefore satisfied the allow
// rule and read raw plaintext — including a prompt-injected agent, for which
// `requesting_tool` is an ordinary argument of the vault_retrieve MCP tool.
//
// The rule this enforces: a caller-asserted identity must never be able to
// collide with one the daemon assigns. Server-set tool names bypass this check
// because they never pass through a request body.
func checkCallerTool(tool string) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tool)), reservedToolPrefix) {
		return fmt.Errorf("tool name %q is reserved: the %q prefix identifies akasha's own internal callers "+
			"and cannot be claimed by a request", tool, reservedToolPrefix)
	}
	return nil
}

// Handler exposes the mux for testing (httptest) and embedding.
func (s *Server) Handler() http.Handler { return s.mux }

// SetPolicyEngine replaces the policy engine (tests, custom policy paths).
//
// It re-applies the state store and notifier, because a replacement engine that
// silently lost them would also lose deleted-policy detection and policy
// lifecycle auditing — a security control disappearing as a side effect of
// swapping an implementation is exactly the kind of thing that is never noticed.
func (s *Server) SetPolicyEngine(e *policy.Engine) {
	e.SetStateStore(s.vlt)
	e.SetNotifier(s.policyNotifier())
	s.policy = e
}

// policyNotifier writes policy lifecycle events to the audit log.
func (s *Server) policyNotifier() policy.Notifier {
	return func(action, detail string) {
		s.auditL.Emit(audit.Event{
			Action:         audit.Action(action),
			AgentID:        "akasha-policy",
			IdentitySource: policy.ServerAssigned.String(),
			ToolName:       "akasha_policy",
			Task:           detail,
		})
	}
}

// splitLabel splits "provider:instance" into its parts. A name with no colon
// is all provider.
func splitLabel(name string) (provider, instance string) {
	if i := strings.Index(name, ":"); i > 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

// authorizeCredentialAccess evaluates action against EVERY name the token is
// reachable under — not just the one the caller asked with — and denies if any
// of them is denied.
//
// Without this, provider/instance rules describe a name the CALLER chose rather
// than the secret itself. `labels.token` is not unique, so binding a second
// name to an existing secret and requesting it under that name walked straight
// past any `provider:`/`instance:` rule:
//
//	POST /label/set {"name":"zz:1","token":"<token behind aws:prod>"}
//	GET  /label/get?name=zz:1        → policy sees provider "zz", not "aws"
//
// Evaluating the union closes it: an alias can never grant access the original
// name would not. Aliases are legitimate (escrow labels, provider aliases), so
// this restricts rather than forbids them. Fail-closed on a lookup error — if
// we cannot enumerate the names, we cannot claim the rules were applied.
func (s *Server) authorizeCredentialNames(_ context.Context, action, requestedName, token string, c caller) error {
	names := []string{requestedName}
	if token != "" {
		bound, err := s.vlt.LabelsForToken(token)
		if err != nil {
			// Fail closed: unable to enumerate the aliases means unable to
			// claim the rules were applied.
			return fmt.Errorf("cannot determine which credentials this token is bound to: %w", err)
		}
		for _, n := range bound {
			if n != requestedName {
				names = append(names, n)
			}
		}
	}
	for _, n := range names {
		provider, instance := splitLabel(n)
		req := c.policyReq(action)
		req.Provider, req.Instance = provider, instance
		req.Category, req.Risk, req.Token = "Credential", "critical", token
		if err := s.policy.Authorize(req); err != nil {
			if n != requestedName {
				return fmt.Errorf("%w (this secret is also bound to %q, whose rules apply)", err, n)
			}
			return err
		}
	}
	return nil
}

// authorizeBind gates pointing a label at a secret — the write side of the
// policy model, and previously ungated entirely.
//
// Two distinct operations share this gate, and they carry different risk:
//
//   - Creating a NEW label is routine (discover/put/setup do it constantly).
//     Risk "high".
//   - RE-POINTING an existing label at a different secret silently changes
//     which credential every future assume, git push, and credential_process
//     call uses. An agent that can do this redirects the human's own tooling
//     at a credential of its choosing. Risk "critical", so `min_risk` can
//     single it out.
//
// The bind is also evaluated against every name the TARGET token already
// answers to, so a rule denying access to a secret also denies minting a fresh
// alias for it — closing the write half of alias laundering while leaving
// legitimate aliases (escrow labels, provider aliases) working.
func (s *Server) authorizeBind(w http.ResponseWriter, r *http.Request, name, token string) bool {
	risk := "high"
	if existing, err := s.vlt.GetLabel(name); err == nil && existing != token {
		risk = "critical"
	}
	c := callerForEndpoint(r, "akasha-bind", "akasha_bind")

	names := []string{name}
	if bound, err := s.vlt.LabelsForToken(token); err == nil {
		for _, n := range bound {
			if n != name {
				names = append(names, n)
			}
		}
	} else {
		http.Error(w, "cannot determine which credentials this token is bound to", http.StatusInternalServerError)
		return false
	}

	for _, n := range names {
		provider, instance := splitLabel(n)
		req := c.policyReq("bind")
		req.Provider, req.Instance = provider, instance
		req.Category, req.Risk, req.Token = "Credential", risk, token
		if !s.authorize(w, req) {
			return false
		}
	}
	return true
}

// authorizeCredentialAccess is the HTTP-writing wrapper around
// authorizeCredentialNames: on denial it emits the DENIED audit event and the
// 403, and the caller must return immediately when it reports false.
func (s *Server) authorizeCredentialAccess(w http.ResponseWriter, action, requestedName, token string, c caller) bool {
	err := s.authorizeCredentialNames(context.Background(), action, requestedName, token, c)
	if err == nil {
		return true
	}
	s.auditL.Emit(audit.Event{
		Token:          token,
		Action:         audit.ActionDenied,
		Category:       "Credential",
		Risk:           "critical",
		AgentID:        c.agentID,
		IdentitySource: c.agentSrc.String(),
		ToolName:       c.tool,
		Task:           err.Error(),
	})
	http.Error(w, err.Error(), http.StatusForbidden)
	return false
}

// authorize evaluates the request against ~/.akasha/policy.yaml, resolving
// "ask" rules interactively. On denial it emits a DENIED audit event and
// writes the 403; the caller must return immediately when it reports false.
func (s *Server) authorize(w http.ResponseWriter, req policy.Request) bool {
	err := s.policy.Authorize(req)
	if err == nil {
		return true
	}
	s.auditL.Emit(audit.Event{
		Token:          req.Token,
		Action:         audit.ActionDenied,
		Category:       req.Category,
		Risk:           req.Risk,
		AgentID:        req.AgentID,
		IdentitySource: req.AgentSource.String(),
		ToolName:       req.Tool,
		// Keep the caller's stated purpose alongside the denial reason. The
		// task used to be REPLACED by the reason, so the one record where you
		// most want to know what the caller claimed it was doing was the one
		// record that dropped it.
		Task: denialTask(req.Task, err),
	})
	http.Error(w, err.Error(), http.StatusForbidden)
	return false
}

// denialTask renders a denial reason without discarding the caller's task.
func denialTask(task string, err error) string {
	if task == "" {
		return err.Error()
	}
	return err.Error() + " — caller stated: " + task
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
// the highest-risk secret among several. Unknown/empty risk ranks lowest, which
// is right here — this only picks a label to display, and an unrankable value
// should not outrank a real "critical".
//
// It delegates to policy.RiskRank so there is one ladder. There used to be two
// implementations of this, and the policy one had to grow an unknown-is-not-
// lowest rule that would have been easy to apply to only one of them.
func riskRank(risk string) int {
	n, _ := policy.RiskRank(risk)
	return n
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
	// Reject a risk label the policy engine cannot rank. `risk` is a free-text
	// body field and /store is not itself policy-gated, so without this a
	// caller could vault an entry as "criticall" — one typo away from a real
	// level, and permanently invisible to every min_risk rule, because an
	// unrankable value matched no threshold. Storing the secret is allowed;
	// storing it with a label that removes it from policy's reach is not.
	if !policy.ValidRisk(req.Risk) {
		http.Error(w, fmt.Sprintf("risk %q is not a known level (want one of %s)",
			req.Risk, strings.Join(policy.RiskLevels(), ", ")), http.StatusBadRequest)
		return
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

	if err := checkCallerTool(req.RequestingTool); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	// Both identity fields here come from the request body, so unless a valid
	// agent key was presented they are Asserted and cannot satisfy an allow.
	polReq := callerFromBody(r, req.AgentID, req.RequestingTool).policyReq("retrieve")
	polReq.Token = polToken
	polReq.Task = req.Task
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
				GrantID:        req.GrantID,
				AgentID:        agentID,
				IdentitySource: polReq.AgentSource.String(),
				Action:         audit.ActionDenied,
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
			GrantID:        req.GrantID,
			Token:          token,
			AgentID:        agentID,
			IdentitySource: polReq.AgentSource.String(),
			Action:         audit.ActionDenied,
			ToolName:       req.RequestingTool,
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
		IdentitySource: polReq.AgentSource.String(),
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

	if err := checkCallerTool(req.AllowedTool); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// grantor_agent and allowed_tool are both body fields — Asserted unless a
	// valid agent key backs them.
	polReq := callerFromBody(r, req.GrantorAgent, req.AllowedTool).policyReq("grant")
	polReq.Token = req.Token
	polReq.Task = req.Task
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

	// Record the identity policy actually evaluated, not the body field. These
	// differ whenever a key was presented: the gate resolved the verified
	// agent, then the log named whoever the request claimed to be — so a
	// key-holding agent could mint a grant durably attributed to someone else.
	s.auditL.Emit(audit.Event{
		Token:          req.Token,
		GrantID:        grantID,
		Action:         audit.ActionGranted,
		AgentID:        polReq.AgentID,
		IdentitySource: polReq.AgentSource.String(),
		ToolName:       polReq.Tool,
		Task:           req.Task,
	})

	jsonOK(w, GrantResponse{GrantID: grantID})
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	grantID := r.URL.Query().Get("grant_id")

	// Resolve the subject BEFORE gating, so the policy request carries the
	// entry's category and risk. The gate used to run first with both fields
	// empty, which meant a `min_risk` rule could never match an inspect — so
	// "deny metadata about critical secrets" silently did nothing. Looking the
	// entry up is not a disclosure; nothing is written to the response until
	// after authorize.
	polReq := callerForEndpoint(r, "akasha-inspect", "akasha_inspect").policyReq("inspect")
	polReq.Token = token

	if token == "" && grantID == "" {
		http.Error(w, "token or grant_id required", http.StatusBadRequest)
		return
	}

	// Look up best-effort and hold any error until AFTER the gate: a denied
	// caller must not be able to tell a real token from an invented one. An
	// unresolvable subject simply carries empty category/risk into the
	// evaluation — which the min_risk rule above now treats as unknown, i.e.
	// restrictive rules still apply.
	var entry interface{}
	var lookupErr error
	if grantID != "" {
		g, err := s.vlt.InspectGrant(grantID)
		lookupErr = err
		if err == nil {
			// A grant's sensitivity is that of the token behind it.
			polReq.Token = g.Token
			if e, err := s.vlt.Inspect(g.Token); err == nil {
				polReq.Category, polReq.Risk = e.Category, e.Risk
			}
			entry = g
		}
	} else {
		e, err := s.vlt.Inspect(token)
		lookupErr = err
		if err == nil {
			polReq.Category, polReq.Risk = e.Category, e.Risk
			entry = e
		}
	}

	if !s.authorize(w, polReq) {
		return
	}
	if lookupErr != nil {
		http.Error(w, lookupErr.Error(), http.StatusNotFound)
		return
	}

	// Emitted on both branches — grant inspection used to return before this
	// and go entirely unlogged, while still disclosing the underlying token.
	s.auditL.Emit(audit.Event{
		Token:    polReq.Token,
		GrantID:  grantID,
		Action:   audit.ActionInspected,
		Category: polReq.Category,
		Risk:     polReq.Risk,
		AgentID:  polReq.AgentID,
		ToolName: polReq.Tool,
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
	// A profile row is a second binding of provider:profile → token, resolved
	// by the same tooling paths as a label, so it is gated as a bind too.
	if !s.authorizeBind(w, r, req.Provider+":"+req.Profile, req.Token) {
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
	// Destructive, and previously reachable unauthenticated by any HTTP verb —
	// including a browser subresource load, since no handler checked the method
	// and a plain <img> request carries a loopback Host and no Origin. Purge
	// deletes discovery-owned entries that no label, profile, or grant reaches,
	// and those roots are themselves caller-writable, so an attacker able to
	// rebind them could turn this into deletion of live credentials.
	purgeReq := callerForEndpoint(r, "akasha-purge", "akasha_purge").policyReq("purge")
	purgeReq.Category, purgeReq.Risk = "Credential", "critical"
	if !s.authorize(w, purgeReq) {
		return
	}
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
	if !s.authorizeBind(w, r, req.Name, req.Token) {
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
	//
	// Resolve the name to a token FIRST so every alias of the same secret is
	// gated too (see authorizeCredentialAccess). This is a name lookup, not a
	// decryption — nothing sensitive happens before the gate. A miss yields an
	// empty token, so an unknown label is evaluated on the requested name alone
	// and still 403s before it 404s: a denied caller learns nothing about which
	// labels exist.
	c := callerForEndpoint(r, "akasha-assume", "akasha_assume")
	token, err := s.vlt.GetLabel(name)
	if !s.authorizeCredentialAccess(w, "assume", name, token, c) {
		return
	}
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
	// Attribute to the caller the gate resolved, not the endpoint's own literal.
	// This path returns a raw value, so hardcoding "akasha-assume" meant the
	// most sensitive disclosure in the daemon was logged under a system
	// pseudo-identity — a key-authenticated agent's read looked exactly like
	// the CLI's.
	s.auditL.Emit(audit.Event{
		Token:          token,
		Action:         audit.ActionRetrieved,
		AgentID:        c.agentID,
		IdentitySource: c.agentSrc.String(),
		ToolName:       c.tool,
		Task:           fmt.Sprintf("Assume label %q", name),
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
	if !s.authorize(w, callerForEndpoint(r, "akasha-list", "akasha_list").policyReq("list")) {
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
	Label    string            `json:"label"`              // e.g. "env:stripe"
	Fields   map[string]string `json:"fields"`             // field → secret value
	Provider string            `json:"provider,omitempty"` // optional, for a profile row
	Profile  string            `json:"profile,omitempty"`
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

	// Gate the binding BEFORE vaulting anything: /put ends in SetLabel, so an
	// agent could otherwise re-point an existing label (say aws:default) at a
	// credential it controls, and the human's next assume or git push would
	// silently authenticate as the attacker. Token is empty here because the
	// map token does not exist yet — a fresh secret has no aliases, so the
	// existing-label check is what carries the risk classification.
	if !s.authorizeBind(w, r, req.Label, "") {
		return
	}

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
		Provider   string `json:"provider"`
		Profile    string `json:"profile"`
		TTLSeconds int    `json:"ttl_seconds,omitempty"`
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

	// A verified agent (one that presented a valid agent key — the MCP tool or an
	// SDK client) must never receive a raw secret in an env var: that lands the
	// credential in its context, defeating assume's "use it without seeing it"
	// contract. Gating on the *verified identity* (not a request flag) means an
	// agent cannot opt in by crafting a raw call. The human CLI is keyless
	// (advisory identity) and may receive raw env values in its own trusted shell.
	// This covers providers whose env delivery materializes a secret field
	// (github/git, source-brokered) and the generic env: provider (tpl == nil,
	// always raw); file-delivered providers (aws/ssh) return a PATH and are exempt.
	if isVerifiedAgent(r) && (tpl == nil || tpl.DeliversSecretEnv()) {
		http.Error(w, fmt.Sprintf("provider %q can't be assumed by an agent — its credential would come back as a raw secret in an env var. Use its credential helper instead (git brokers per fetch/push via `akasha helper %s` in a session set up by `akasha setup`), or vault_retrieve if you explicitly need the value.", req.Provider, req.Provider), http.StatusForbidden)
		return
	}

	c := callerForEndpoint(r, "akasha-assume", "akasha_assume")

	resolved, err := s.credsFor(r.Context(), "assume", req.Provider, req.Profile, c)
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
	// NOTE: /assume's raw-secret refusal is deliberately NOT mirrored here, and
	// the asymmetry is a real residual risk worth stating plainly.
	//
	// /assume refuses to hand a verified agent a provider whose delivery
	// materializes a raw secret, because that lands the value in the session
	// environment. The same refusal cannot be applied to /resolve: the git and
	// aws credential helpers are *supposed* to run inside an agent session and
	// resolve github/aws per operation, and those are exactly the providers
	// DeliversSecretEnv() flags. Refusing them here would break the broker the
	// product is built around.
	//
	// Nor can the daemon tell `akasha helper` (which renders the fields into
	// the provider's wire protocol) from an agent calling /resolve directly to
	// read them: both are same-UID HTTP requests over the socket, and any
	// distinguishing marker a caller could send is one a caller could forge.
	// Honest peer attestation (LOCAL_PEERTOKEN / SO_PEERCRED on the socket) is
	// the fix, and is tracked as its own rung in docs/design/same-user-identity.md.
	//
	// What DOES constrain this path is the "broker" policy verb: it is separate
	// from "assume", so a user can gate or deny per-operation brokering on its
	// own terms. That is the control; this comment is the disclosure.
	creds, err := s.credsFor(r.Context(), "broker", provider, instance,
		callerForEndpoint(r, "akasha-helper", "akasha_helper"))
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
// action is "assume" (materialize a credential for a session) or "broker"
// (resolve one for a single operation, the helper path). They are separate
// policy verbs on purpose: brokered per-operation USE is the low-risk path a
// user wants to permit routinely, while an assume hands over a working
// credential for a whole session. Collapsing them into one verb forced anyone
// who wanted the broker to also allow assume.
func (s *Server) credsFor(ctx context.Context, action, provider, instance string, c caller) (map[string]string, error) {
	agentID, tool := c.agentID, c.tool
	// Policy gate. Either path hands out a full working credential, so the
	// request is evaluated as critical-risk regardless of how the underlying
	// entries were classified.
	//
	// The label is resolved to a token first (a name lookup, not a decryption)
	// so every alias bound to the same secret is gated too — otherwise binding
	// a fresh name to a vaulted credential and asking for it under that name
	// walks past any provider/instance rule. Source-backed providers have no
	// label; they evaluate on the requested name alone.
	label := provider + ":" + instance
	mapToken, labelErr := s.vlt.GetLabel(label)
	if err := s.authorizeCredentialNames(ctx, action, label, mapToken, c); err != nil {
		s.auditL.Emit(audit.Event{
			Action:         audit.ActionDenied,
			Category:       "Credential",
			Risk:           "critical",
			AgentID:        agentID,
			IdentitySource: c.agentSrc.String(),
			ToolName:       tool,
			Task:           err.Error(),
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
			Action:         audit.ActionRetrieved,
			AgentID:        agentID,
			IdentitySource: c.agentSrc.String(),
			ToolName:       tool,
			Task:           fmt.Sprintf("Brokered %s:%s from %s backend (on-demand, not stored)", provider, instance, tpl.Source[0].Backend),
		})
		return creds, nil
	}

	// Vault path: label "aws:default" → credential-map token → field tokens.
	// The lookup was hoisted above the policy gate so aliases could be gated;
	// its error is reported here, after authorization, so a denied caller still
	// cannot use the 404 to probe which labels exist.
	if labelErr != nil {
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
		Token:          mapToken,
		Action:         audit.ActionRetrieved,
		AgentID:        agentID,
		IdentitySource: c.agentSrc.String(),
		ToolName:       tool,
		Task:           credsTask(action, provider, instance),
	})
	return resolved, nil
}

// credsTask renders the audit description for a credsFor vend. The wording is
// derived from the action the server chose, never from caller-supplied text, so
// the audit trail cannot be dressed up by the thing being audited.
func credsTask(action, provider, instance string) string {
	if action == "broker" {
		return fmt.Sprintf("Brokered %s:%s for one operation (helper)", provider, instance)
	}
	return fmt.Sprintf("Assume %s:%s", provider, instance)
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
