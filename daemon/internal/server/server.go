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
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
	"github.com/inferlabshq/akasha/daemon/internal/audit"
	"github.com/inferlabshq/akasha/daemon/internal/classifier"
	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/identity"
	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/resolve"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

const HTTPPort = 7743

// MaxUnixSocketPath is the smallest sun_path limit across supported platforms
// (104 on darwin, 108 on Linux). Checked rather than assumed, because going
// over it fails with an unexplained "invalid argument".
const MaxUnixSocketPath = 104

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
	// Set by Shutdown, read by serve, both under mu — see serve.
	shuttingDown bool

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
	s.mux.HandleFunc("/identity", get(s.auth(s.handleIdentity)))
	s.mux.HandleFunc("/label/set", post(s.auth(s.handleLabelSet)))
	s.mux.HandleFunc("/credential/retrieve", get(s.auth(s.handleCredentialRetrieve)))
	s.mux.HandleFunc("/label/list", get(s.auth(s.handleLabelList)))
	s.mux.HandleFunc("/label/delete", post(s.auth(s.handleLabelDelete)))
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

// keylessRefusal is the 401 a request carrying no X-Akasha-Key receives.
//
// It names the CLI key file, because the overwhelmingly common cause is a
// daemon that has not provisioned one yet (started before this version, or
// started against a --db whose data dir the CLI is not reading).
const keylessRefusal = "no agent key presented — every caller must authenticate, including the local CLI. " +
	"The daemon provisions the CLI's key at startup (cli.key in the vault's data directory); if you are seeing " +
	"this from `akasha`, restart the daemon so it can write one. Agents get theirs from `akasha setup`."

// auth is middleware that establishes WHO is calling, and refuses anyone it
// cannot name.
//
//   - Valid key: the verified agent_id is injected into the context, where it
//     overrides whatever agent_id the request body claims.
//   - Invalid or revoked key: 401.
//   - No key: 401.
//
// That last line is the security property, and it is a deliberate reversal.
//
// A keyless request used to pass through and be treated as the trusted local
// human, which made authentication REDUCE privilege: the keyless path was
// granted raw secret delivery and `akasha run` that a verified agent was
// refused. So `akasha agent revoke` did not lock an agent out — the agent
// dropped the header and came back with MORE authority than its key had
// carried. Revocation removed an identity while leaving the access path wide
// open, and the rational move for any local process was never to authenticate.
//
// Refusing the keyless caller makes privilege monotonic in authentication:
// presenting less can only ever get you less. The human CLI now holds a real
// identity (vault.IdentityCLI) provisioned by the daemon at startup, so the
// human path is granted on an affirmative, revocable, auditable identity rather
// than on an absence the daemon has no way to verify.
//
// /health is exempt and is registered without this middleware — liveness must
// be answerable before a key exists, and it discloses nothing.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Akasha-Key")
		if key == "" {
			http.Error(w, keylessRefusal, http.StatusUnauthorized)
			return
		}
		agentID, err := s.vlt.VerifyAgentKey(key)
		switch {
		case errors.Is(err, vault.ErrAgentKeyRevoked):
			http.Error(w, "agent key has been revoked — if this was not intended, issue a new one with "+
				"`akasha agent resync --rotate`. Dropping the key from the request will not help: an "+
				"unauthenticated caller is refused outright.", http.StatusUnauthorized)
			return
		case errors.Is(err, vault.ErrAgentKeyInvalid):
			http.Error(w, "agent key not recognised by the vault (likely after a vault rebuild) — run "+
				"`akasha agent resync` to re-authorize this key, then retry. No restart needed.",
				http.StatusUnauthorized)
			return
		case err != nil:
			// Anything else is the VAULT failing, not the key being bad. These
			// must not be reported as 401: now that every request is
			// authenticated, an unreadable vault would turn every endpoint into
			// "your key is wrong" and send users to re-mint perfectly good keys
			// chasing a storage fault.
			http.Error(w, "cannot verify agent key — the vault is not readable: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		// Inject verified identity into context — handlers read this
		// and it wins over whatever agent_id is in the request body.
		ctx := context.WithValue(r.Context(), ctxAgentID, agentID)

		// A supervised run is recognised by the key it authenticated with, so
		// its capability profile applies on every listener the daemon has.
		// Binding it to the run's private socket instead left the profile
		// optional: nothing confines the sandbox's network, so the same key
		// reached the loopback port and got the unrestricted mux.
		run, stale := s.runForKey(agentID, key)
		if stale {
			http.Error(w, staleRunRefusal, http.StatusUnauthorized)
			return
		}
		if run != nil {
			ctx = context.WithValue(ctx, ctxRun, run)
		}
		r = r.WithContext(ctx)
		if run != nil && !s.runCapabilities(w, r, run) {
			return
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
	// sandboxed is set when the caller authenticated as a live supervised run —
	// established by the key the daemon verified, not by the caller.
	sandboxed bool
	// runID names that run, and human reports whether this is the local CLI.
	//
	// Both were already established here and thrown away. runFrom(r) was called
	// only for its nil-ness, so a run that brokered 200 git operations emitted
	// 200 audit events with no join key back to its own run_begin — the one
	// place per-operation brokering pays off in attribution was the one place
	// the correlation was missing.
	runID string
	human bool
}

// withRun fills in everything the daemon knows about the caller from the
// request itself — never from its body. Factored out so the two constructors
// cannot drift: they were one function once, and splitting them is what made
// the trust level of an identity visible at the point of use.
func (c *caller) withRun(r *http.Request) {
	run := runFrom(r)
	c.sandboxed = run != nil
	if run != nil {
		c.runID = run.ID
	}
	c.human = isHuman(r)
}

// assumeCaller is the caller context a TTL ceiling depends on. Both fields come
// from the verified key, so neither is anything a request body can assert.
func (c caller) assumeCaller(runDeadline time.Time) assume.Caller {
	return assume.Caller{Human: c.human, RunDeadline: runDeadline}
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
		Human:       c.human,
	}
}

// callerFromBody builds the identity for an endpoint where the CALLER names
// itself — /wrap, /store, /retrieve, /grant. A verified key wins; otherwise the
// body values are marked Asserted, so no allow rule can be satisfied by them.
func callerFromBody(r *http.Request, bodyAgentID, bodyTool string) caller {
	c := caller{agentID: bodyAgentID, agentSrc: policy.Asserted, tool: bodyTool, toolSrc: policy.Asserted}
	c.withRun(r)
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
// An AGENT's verified identity replaces the endpoint literal, because "which
// agent is brokering this" is what a policy rule wants to match. The HUMAN CLI
// keeps the literal: on these endpoints the useful name is the internal path
// that is running (akasha-list, akasha-helper, akasha-assume), which is what
// existing rules are written against.
//
// That split is what the keyless caller used to get for free, and it survives
// the move to mandatory authentication — but it is now stronger than it was.
// The literal previously went to ANY caller that presented no key; it now
// requires authenticating as vault.IdentityCLI, so a rogue process can no
// longer land on a server-assigned name by staying anonymous.
func callerForEndpoint(r *http.Request, literalAgent, literalTool string) caller {
	c := caller{agentID: literalAgent, agentSrc: policy.ServerAssigned, tool: literalTool, toolSrc: policy.ServerAssigned}
	c.withRun(r)
	if v, ok := r.Context().Value(ctxAgentID).(string); ok && v != "" && v != vault.IdentityCLI {
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

// isHuman reports whether this request came from the local human CLI — that is,
// whether it presented a valid key bound to the reserved vault.IdentityCLI.
//
// This replaces an isVerifiedAgent() that answered the same question by
// NEGATION: "no verified identity, therefore the human." Every gate written
// that way failed open. A caller that presented nothing satisfied it, so the
// two most privileged paths in the daemon — raw secret delivery through
// /assume, and starting an `akasha run` — were reachable by presenting less
// than an agent key rather than more. Asking for the identity affirmatively
// means the gates fail closed: an unknown caller is not the human, and (since
// auth now refuses keyless requests) never even reaches here.
//
// The identity is not forgeable through the request body — it comes from the
// context, which only a verified key populates — and IdentityCLI cannot be
// minted by `akasha agent create` (see vault.ReservedAgentID). It IS readable
// by a same-uid process from the 0600 key file; see the ceiling note in
// internal/clikey.
func isHuman(r *http.Request) bool {
	v, ok := r.Context().Value(ctxAgentID).(string)
	return ok && v == vault.IdentityCLI
}

// ── The escrow namespace belongs to the human ───────────────────────────────
//
// `akasha protect` moves a credential FILE into the vault: the entry's value is
// that file's verbatim bytes. So for escrow — and only for escrow — reading the
// entry IS reading the plaintext the user took off disk. Every other credential
// the vault holds has a brokered form, where a tool gets USE of it without the
// value entering anyone's context; an escrowed file has none, because the thing
// being protected is the file itself.
//
// Escrow is therefore the one namespace where USE-vs-READ has to be drawn by
// IDENTITY rather than by verb, and the daemon draws it here rather than in
// policy:
//
//   - A policy rule does not close it. /credential/retrieve is gated as
//     `assume`, and `assume` ships permissive so routine git/aws work is not
//     interrupted — which handed any key-holding agent a whole credentials file
//     in one request under the shipped default. Shipping the
//     `{action: assume, provider: escrow}` rule docs/POLICY.md used to
//     recommend is not the fix either: as `ask` it fails closed on a headless
//     machine and locks the OWNER out of their own file, and as `deny` it does
//     so outright. That recommendation has been removed.
//   - The owner loses nothing. `akasha protect` and `akasha restore` run as the
//     local CLI, and `akasha uninstall` restores through the vault directly
//     without crossing this boundary. Policy still evaluates first, so an
//     operator who wants to restrict themselves further still can.
//   - No agent path needs it. An agent brokers aws:default or github:default —
//     separate entries that protect never touches. Nothing an agent legitimately
//     does reads, lists, binds or unbinds an `escrow:` label.
//
// Same-uid remains the ceiling: a process that steals cli.key is the human as
// far as this gate can tell (docs/design/same-user-identity.md). What it stops
// is an agent using the identity it was GIVEN to undo protect.

// escrowName reports whether a label is in the escrow namespace.
// Case-INSENSITIVELY, because the gate and the lookup have to agree on what
// counts as an escrow label and they did not: this test was case-sensitive
// while the vault resolves prefixes with SQL `LIKE`, which is case-insensitive
// for ASCII. So `ESCROW:` failed the gate and matched in the database — enough
// to enumerate every escrowed path out of a 404's hint, and to squat the
// namespace with /label/set so the owner's `restore --all` failed for good.
//
// Deliberately not "normalise the name on the way in": labels are user data and
// case may matter elsewhere. What must never disagree is the GUARD and the
// LOOKUP, so the guard is widened to whatever the lookup would match.
func escrowName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), escrow.LabelPrefix)
}

// isEscrowProvider is escrowName's other half, for the endpoints that receive a
// provider rather than a whole label.
//
// Widening escrowName alone was not enough: two callers compare the provider
// DIRECTLY, and stayed case-sensitive after the label test stopped being. That
// left `/resolve?provider=ESCROW` listing every escrowed path — the same
// enumeration the label test had just been widened to stop, through the one
// door that never asked it. Both spellings of the question now share an answer.
func isEscrowProvider(provider string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), escrow.Provider)
}

// escrowToken reports whether a token holds an escrowed file.
//
// By CATEGORY, which is written when the entry is stored, not by the name the
// caller asked with: `labels.token` is not unique, so a fresh alias bound to an
// escrow entry would otherwise walk this guard exactly the way alias laundering
// walked the policy gate (see authorizeCredentialNames).
func (s *Server) escrowToken(token string) bool {
	if token == "" {
		return false
	}
	e, err := s.vlt.Inspect(token)
	return err == nil && e.Category == escrow.Category
}

// denyEscrow writes the 403 and the DENIED audit record for a non-human caller
// that reached an escrow entry. Callers must return immediately after it.
func (s *Server) denyEscrow(w http.ResponseWriter, verb, what string, token string, c caller) {
	if what == "" {
		what = token
	}
	msg := fmt.Sprintf("%q is an escrowed file — the verbatim contents of a credential file its owner moved "+
		"into the vault with `akasha protect`. An agent may not %s it. Escrowed files belong to the human: "+
		"reading one hands back the plaintext they took off disk, and unbinding or re-pointing its label "+
		"destroys the only copy. Use the credential through its broker instead (`akasha helper <provider>`, "+
		"or vault_assume).", what, verb)
	s.auditL.Emit(audit.Event{
		Token:          token,
		Action:         audit.ActionDenied,
		Category:       escrow.Category,
		Risk:           "critical",
		AgentID:        c.agentID,
		IdentitySource: c.agentSrc.String(),
		ToolName:       c.tool,
		Task:           msg,
	})
	http.Error(w, msg, http.StatusForbidden)
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

// missingProviderProfile is the answer to a call that arrived without the two
// arguments the credential endpoints take. It used to be the bare "provider and
// profile required", which was a third of the failed first calls on the agent
// surface and named neither the shape it wanted nor a next call — the error
// shape a model answers by inventing a tool name rather than by fixing the
// call. The one message on this surface that reliably recovered a caller named
// the recovery ("call vault_status to see which pairs exist"), so this is that
// message, plus the single-label form: a caller that has seen `aws:default`
// written anywhere passes it as one argument, and being told to split it on the
// colon is the whole fix.
func missingProviderProfile(tool string) string {
	return fmt.Sprintf("provider and profile required — %s takes them as two separate arguments, "+
		"e.g. provider=\"aws\", profile=\"default\". A single \"aws:default\" label is not one of them; "+
		"if that is what you have, split it on the colon. Call vault_status to see which pairs exist.", tool)
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
//	GET  /credential/retrieve?name=zz:1        → policy sees provider "zz", not "aws"
//
// Evaluating the union closes it: an alias can never grant access the original
// name would not. Aliases are legitimate (escrow labels, provider aliases), so
// this restricts rather than forbids them. Fail-closed on a lookup error — if
// we cannot enumerate the names, we cannot claim the rules were applied.
// riskOfAction classifies what a credential action can hand back, which is what
// min_risk rules are written against.
//
// Every credential action — DESCRIBE included — is critical. That is
// deliberate, and it is NOT a claim that an account number is as sensitive as a
// secret key. It is a claim about upgrades: `min_risk` matches "at or above",
// so an operator whose policy says `min_risk: critical → deny` covers every
// credential action they have today. Rating a NEW action lower would slide it
// out from under that rule the moment they upgraded — their policy file
// unchanged, their coverage quietly smaller, no diff to review. A security
// product must not widen access as a side effect of a version bump.
//
// Operators who want frictionless describes opt IN, which is one rule:
//
//   - action: describe
//     effect: allow
//
// The default path is unaffected: with no policy installed the engine allows
// everything, so `akasha whoami` works out of the box.
func riskOfAction(string) string { return "critical" }

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
		req.Category, req.Risk, req.Token = "Credential", riskOfAction(action), token
		// Whether this provider HAS a per-operation route is a fact the
		// template already declares — a helper deliver mode plus a vending
		// ownership mechanism. The daemon reads it; it does not decide with it.
		// That is what keeps "may an agent hold a session credential for this
		// provider" an operator's rule rather than a branch in Go.
		req.Brokerable = template.Get(provider).Brokerable()
		if err := s.policy.Authorize(req); err != nil {
			if n != requestedName {
				return fmt.Errorf("%w (this secret is also bound to %q, whose rules apply)", err, n)
			}
			return err
		}
	}
	return nil
}

// aliasNames returns name plus every OTHER label the token answers to.
//
// `labels.token` is not unique, so one secret can carry any number of names.
// Gating a write on the name in the REQUEST alone therefore gates a name the
// caller chose, and every write gate must walk this whole set instead.
func (s *Server) aliasNames(name, token string) ([]string, error) {
	names := []string{name}
	if token == "" {
		return names, nil
	}
	bound, err := s.vlt.LabelsForToken(token)
	if err != nil {
		return nil, err
	}
	for _, n := range bound {
		if n != name {
			names = append(names, n)
		}
	}
	return names, nil
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
func (s *Server) authorizeBind(w http.ResponseWriter, r *http.Request, name, token, declaredAgentID string) bool {
	risk := "high"
	existing, existingErr := s.vlt.GetLabel(name)
	rebind := existingErr == nil && existing != token
	if rebind {
		risk = "critical"
	}
	c := callerForEndpoint(r, "akasha-bind", "akasha_bind")

	// The write half of the escrow gate. Re-pointing `escrow:/home/me/.aws/
	// credentials` at a token of the agent's choosing orphans the only copy of
	// the user's file just as thoroughly as deleting the label, and minting a
	// fresh alias for an escrow token is the read gate's alias-laundering move
	// with the steps reversed. Neither is anything an agent legitimately does.
	if !isHuman(r) && (escrowName(name) || s.escrowToken(token)) {
		s.denyEscrow(w, "bind", name, token, c)
		return false
	}

	// Re-pointing ANY existing label is a human-only act, not just an escrow
	// one.
	//
	// The escrow gate above closed one namespace and left the rest open, and the
	// rest is where the user's working credentials live: an agent could bind
	// `aws:default` to a token of its choosing with no invented value and no
	// spoofed name — a well-formed key it had stored a moment earlier was
	// enough. The real credential is then orphaned, every later assume resolves
	// to the agent's, and the audit log records a successful bind. No value
	// check can catch that, because nothing about the value is wrong; what is
	// wrong is that a name the human relies on now means something else.
	//
	// CREATING a name is left open on purpose. An agent vaulting something of
	// its own and giving it a label is ordinary work, and refusing it would push
	// callers toward reusing a name that already exists — the very thing this
	// stops. So the rule is the narrow one: you may add a name, you may not take
	// one over.
	if rebind && !isHuman(r) {
		msg := fmt.Sprintf("%q already names a different credential, and re-pointing an existing name is "+
			"something only the person at the keyboard does — every tool that resolves %q would silently "+
			"start getting the new value. Vault yours under a name of its own (vault_put with a label you "+
			"choose), or ask the human to re-point this one.", name, name)
		s.auditL.Emit(audit.Event{
			Token:          token,
			Action:         audit.ActionDenied,
			Risk:           "critical",
			AgentID:        c.agentID,
			IdentitySource: c.agentSrc.String(),
			ToolName:       c.tool,
			Task:           msg,
		})
		http.Error(w, msg, http.StatusForbidden)
		return false
	}

	// The same refusal for the OWNER, because identity is not what makes this
	// safe — an escrow label is the only handle on a file its owner took off
	// disk, so re-pointing it destroys that file whoever types the command.
	// /label/delete refused this and /put did not, which left the whole guard
	// as a fence around one of two doors: `akasha put escrow:<path> --stdin`
	// printed "✓ stored", after which `akasha restore` failed on a path
	// mismatch and `akasha uninstall` could not put the file back either.
	//
	// Re-protecting the same file is exempt, and is the only exemption: there
	// the replacement entry is a fresher copy of the same bytes.
	if rebind && escrowName(name) && !s.escrowEnvelopeFor(token, strings.TrimPrefix(name, escrow.LabelPrefix)) {
		if path, onlyCopy := s.escrowOnlyCopy(name, existing); onlyCopy {
			http.Error(w, fmt.Sprintf("%q is the only name for the escrowed original of %s, and that file is "+
				"not back on disk — pointing this name at anything else would destroy it. Escrow entries are "+
				"created by `akasha protect`, not by `akasha put`. Put the file back first with "+
				"`akasha restore %s`, after which the name is free. If you do not want the escrowed bytes "+
				"back at all, say so by name first: `akasha label rm --destroy-escrowed-original %s`.",
				name, path, path, name), http.StatusConflict)
			return false
		}
	}

	names, err := s.aliasNames(name, token)
	if err != nil {
		http.Error(w, "cannot determine which credentials this token is bound to — retry, and check the vault is readable with `akasha status`", http.StatusInternalServerError)
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
		Risk:           riskOfAction(action),
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
// Shutdown. Returns nil on a clean shutdown, and serves nothing at all if
// Shutdown already ran.
//
// The registration and the already-shutting-down check share s.mu because a
// listener that registers itself AFTER Shutdown walked the list is never
// stopped, and startCmd waits for every listener before it returns. The
// daemon then keeps serving credentials with its termination signals already
// trapped — SIGTERM does nothing from then on and only SIGKILL ends it — while
// the operator has been told it stopped. The window is only the microseconds
// between the "listening on" log line and this lock, but a stop signal timed
// on that line hung 2 starts in 60 under test.
func (s *Server) serve(ln net.Listener, h http.Handler) error {
	hs := &http.Server{Handler: h}
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		ln.Close()
		return nil
	}
	s.httpServers = append(s.httpServers, hs)
	s.mu.Unlock()
	if err := hs.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ListenUnix starts the Unix socket listener (primary, fastest path).
func (s *Server) ListenUnix(socketPath string) error {
	// sun_path is a fixed-size field in the kernel's sockaddr_un — 104 bytes on
	// darwin, 108 on Linux — and exceeding it fails with a bare "invalid
	// argument" that names neither the limit nor the length. A daemon started
	// under a long temp path therefore dies for a reason nothing on screen
	// explains, and clients then fall back to the shared HTTP port and reach a
	// different daemon entirely. Diagnose it here, where the number is known.
	if len(socketPath) >= MaxUnixSocketPath {
		return fmt.Errorf("unix socket path is %d bytes, over the %d-byte OS limit: %s\n"+
			"  Use a shorter path (e.g. under /tmp) — the kernel's sockaddr_un field is fixed-size",
			len(socketPath), MaxUnixSocketPath, socketPath)
	}
	// A socket file left behind by a daemon that was killed would fail this
	// bind with "address already in use", so it is cleared first. Its presence
	// is not evidence of a running daemon either way: a clean stop unlinks it
	// (Go's UnixListener does that on Close) and a kill leaves it. Dialling is
	// the only test that means anything.
	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("unix socket: %w", err)
	}
	// A unix socket is created 0777 &^ umask, so on a default umask every local
	// account could connect to the daemon's primary endpoint.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("unix socket: cannot restrict %s to this user: %w\n"+
			"  The daemon refuses to serve a socket other accounts can open", socketPath, err)
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

// Shutdown gracefully stops every listener started via Listen*, and closes the
// server to any that has not registered itself yet (see serve). It is one-way:
// a Server that has been shut down does not serve again.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.shuttingDown = true
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
	// The same fail-closed guard on the other classification axis. `category` is
	// a free-text body field too, so a caller could vault an entry under a blank
	// or unwritable label and put it out of reach of every `category:` rule.
	if !policy.ValidCategory(req.Category) {
		http.Error(w, fmt.Sprintf("category %q cannot be named by a policy rule — use 1-64 characters of "+
			"letters, digits, '.', '_' or '-' (akasha's own categories are %s)",
			req.Category, strings.Join(policy.CategoryLevels(), ", ")), http.StatusBadRequest)
		return
	}

	// And the third axis: the value itself. The two checks above police the
	// LABELS a caller attaches; nothing looked at what was being labelled, so an
	// agent that needed a credential and did not have one could invent a string,
	// store it under a real category, and report the problem solved — observed
	// verbatim in agent testing, with "my_secret_value" vaulted as an AWS key.
	// A decoy in the vault is worse than a refusal: it is indistinguishable from
	// the real entry until something tries to authenticate with it.
	//
	// Human-only, and deliberately so. `akasha protect` pushes whole credential
	// FILES through this endpoint and `akasha discover` pushes whatever is
	// actually in the user's config — including the deliberately unrealistic
	// keys a LocalStack or MinIO setup uses. The user is allowed to vault a
	// value that does not look like a credential; a caller that cannot see the
	// value it is claiming to hold is not.
	// No provisioning exemption. There was one, on the reasoning that a value
	// akasha had just read off this machine's disk is the user's whatever it
	// looks like — which is true right up until an agent writes the file. An
	// agent that can create ~/.env can put its own token where discovery will
	// find it and bind it to the human's names, and no check here can tell those
	// bytes apart. `akasha discover` now refuses inside an agent session instead,
	// which is where that distinction can actually be drawn.
	if len(req.Content) > maxAgentSecretBytes && !isHuman(r) {
		http.Error(w, fmt.Sprintf("content is %d bytes — that is a file, not a credential. "+
			"To take a credential FILE off disk, the person at the keyboard runs `akasha protect <path>`",
			len(req.Content)), http.StatusBadRequest)
		return
	}
	if !isHuman(r) {
		if err := checkStoredValue(req.Category, req.Content); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
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

// maxAgentSecretBytes bounds what a caller other than the human may push into
// the vault in one /store. No credential is anywhere near this large — a 4096-bit
// RSA private key is about 3 KiB — so the cap only ever catches an agent
// redirecting a file or a transcript into the vault. The human's own paths
// (`akasha protect` escrows whole files) are not subject to it.
const maxAgentSecretBytes = 64 * 1024

// checkStoredValue rejects a value that cannot be the credential its caller
// says it is. It answers only two questions — is this a placeholder, and does
// it have the form this category requires — and says nothing about categories
// whose shape is a convention rather than a fact.
//
// Every message names the tool to use instead, because the caller is usually a
// model: an error that only says "no" is answered by inventing a different tool
// name, while one that names the next call is answered by making it.
//
// What it must NOT name is vault_put. That was the first version of this
// message — "use vault_put(label=…) instead" — and it turned a caught mistake
// into an uncaught one: the caller took the rejected value straight to the one
// endpoint that BINDS A LABEL, where junk does not sit beside the real entry
// but replaces it. Three tool calls took a made-up key from "vault_store
// refused this" to aws:default resolving to it. A caller that does not have a
// credential is routed to the tools that find and use the one already vaulted,
// never to another way of writing.
func checkStoredValue(category, content string) error {
	if len(content) > maxAgentSecretBytes {
		return fmt.Errorf("content is %d bytes — that is a file, not a credential. "+
			"To take a credential FILE off disk, the person at the keyboard runs `akasha protect <path>`",
			len(content))
	}
	if classifier.LooksFabricated(content) {
		return fmt.Errorf("that value is a placeholder, not a credential — storing it would put a decoy " +
			"in the vault next to the real entry. If you do not have the secret, do not invent one: call " +
			"vault_status to see what is already vaulted, then vault_assume(provider, profile) to USE it")
	}
	shape, known := classifier.ShapeFor(category)
	if known && !shape.Re.MatchString(strings.TrimSpace(content)) {
		return fmt.Errorf("that value is not a %s — a %s is %s. If it is a secret of some other kind, "+
			"pass the category that fits (or \"UserSecret\"); if you do not have the real value, do not "+
			"invent one: call vault_status to see what is already vaulted, then "+
			"vault_assume(provider, profile) to USE it",
			category, category, shape.Want)
	}
	return nil
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
	bodyCaller := callerFromBody(r, req.AgentID, req.RequestingTool)
	polReq := bodyCaller.policyReq("retrieve")
	polReq.Token = polToken
	polReq.Task = req.Task
	if entry, err := s.vlt.Inspect(polToken); err == nil {
		polReq.Category = entry.Category
		polReq.Risk = entry.Risk
	}
	if !s.authorize(w, polReq) {
		return
	}

	// The escrow gate, on the token that will actually be decrypted — polToken
	// is the grant's token when this is a redemption, so a grant cannot be used
	// to launder an escrowed file to a second agent. Checked BEFORE the redeem
	// below so a refusal does not also burn a single-use grant.
	if !isHuman(r) && s.escrowToken(polToken) {
		s.denyEscrow(w, "read", "", polToken, bodyCaller)
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
		AgentID  string            `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.Provider == "" || req.Profile == "" || req.Token == "" {
		http.Error(w, "provider, profile, and token required", http.StatusBadRequest)
		return
	}
	// A profile row is a second binding of provider:profile → token, resolved
	// by the same tooling paths as a label, so it is gated as a bind too.
	if !s.authorizeBind(w, r, req.Provider+":"+req.Profile, req.Token, req.AgentID) {
		return
	}
	if err := s.vlt.SaveProfile(req.Provider, req.Profile, req.Token, req.Metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// handleIdentity answers "who is this credential?" without disclosing or using
// it — Akasha's DESCRIBE path.
//
// The design constraints, in the order they are enforced below:
//
//  1. Authorize BEFORE disclosing anything, including whether the provider or
//     profile exists. Otherwise the error messages become an enumeration oracle
//     for a caller the policy denies.
//  2. Only a TRUSTED template may drive a derivation. A template decides which
//     fields are secret, and step 4 acts on that, so an untrusted or edited
//     template must not get a vote.
//  3. Refuse source-backed providers. Fetching from an upstream manager pulls
//     the whole credential and makes a network call — the opposite of what
//     DESCRIBE promises. Better to refuse than to quietly escalate.
//  4. Decrypt the MINIMUM. The contract names the fields it reads; each must be
//     declared non-secret by the provider; only those are unwrapped. The secret
//     half of the credential is never decrypted, so it cannot leak from a
//     process that never held it.
//
// Nothing is cached, written to disk, or materialized into a session, and no
// network call is made — so this endpoint cannot become a credential-delivery
// path, an exfiltration trigger, or a cache an attacker can poison.
func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	profile := r.URL.Query().Get("profile")
	if provider == "" || profile == "" {
		http.Error(w, missingProviderProfile("vault_identity"), http.StatusBadRequest)
		return
	}

	c := callerForEndpoint(r, "akasha-describe", "akasha_describe")

	// (1) Gate first. Every message after this point can disclose existence.
	if err := s.authorizeCredentialNames(r.Context(), "describe", provider+":"+profile, "", c); err != nil {
		s.auditL.Emit(audit.Event{
			Action:         audit.ActionDenied,
			Category:       "Credential",
			Risk:           riskOfAction("describe"),
			AgentID:        c.agentID,
			IdentitySource: c.agentSrc.String(),
			ToolName:       c.tool,
			Task:           err.Error(),
		})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	tpl := template.Get(provider)
	desc := (*template.DeliverMode)(nil)
	if tpl != nil {
		desc = tpl.DescribeDeliver()
	}
	if desc == nil {
		http.Error(w, fmt.Sprintf("provider %q declares no describe deliver mode, so there are no facts to derive from it", provider), http.StatusNotFound)
		return
	}

	// (2) An untrusted template must not influence which fields get decrypted.
	store, terr := trust.Load()
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusInternalServerError)
		return
	}
	if ok, _ := store.Approved(tpl); !ok {
		http.Error(w, fmt.Sprintf("template %q is not trusted yet — review it with `akasha template explain %s`, then approve once with `akasha template trust %s`", provider, provider, provider), http.StatusForbidden)
		return
	}

	// (3) Source-backed providers would make DESCRIBE fetch the whole
	// credential over the network. Refuse rather than silently escalate.
	if len(tpl.Source) > 0 {
		http.Error(w, fmt.Sprintf("provider %q resolves its credential from an external backend, so describing it would fetch the full secret over the network — refusing. Use the provider's own tooling if you need this.", provider), http.StatusConflict)
		return
	}

	// (4) Decrypt only what the contract reads, and only if the provider agrees
	// those fields are non-secret.
	needed, err := identity.RequiredFields(desc.Contract)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if bad := secretFieldAmong(tpl, needed); bad != "" {
		http.Error(w, fmt.Sprintf("identity contract %q reads field %q, which provider %q declares secret — refusing to decrypt a secret for a describe",
			desc.Contract, bad, provider), http.StatusConflict)
		return
	}

	resolved, err := s.credsFor(r.Context(), "describe", provider, profile, c, needed...)
	if err != nil {
		http.Error(w, err.Error(), credsErrStatus(err))
		return
	}

	derived, err := identity.Derive(desc.Contract, resolved)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// The template's map is the disclosure list: the contract computed
	// everything it knows, and only what this provider chose to expose leaves
	// the daemon. That decision belongs to the reviewable, signed artifact, not
	// to the daemon or the caller.
	facts := derived.Reveal(desc.Map)

	s.auditL.Emit(audit.Event{
		Action:         audit.ActionDescribed,
		Category:       "Credential",
		Risk:           riskOfAction("describe"),
		AgentID:        c.agentID,
		IdentitySource: c.agentSrc.String(),
		ToolName:       c.tool,
		Task:           fmt.Sprintf("Derived non-secret identity facts for %s:%s via %s", provider, profile, facts.Contract),
	})

	jsonOK(w, identityResponse{
		Provider: provider, Profile: profile,
		Facts:  facts.Values,
		Source: facts.Source, Offline: facts.Offline,
		Contract: facts.Contract, DerivedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// identityResponse is the wire shape of a DESCRIBE. Source and Offline travel
// with the facts on purpose: a caller acting on an account number should be
// able to see whether it was decoded locally or confirmed by the provider.
type identityResponse struct {
	Provider  string            `json:"provider"`
	Profile   string            `json:"profile"`
	Facts     map[string]string `json:"facts"`
	Source    string            `json:"source"`
	Offline   bool              `json:"offline"`
	Contract  string            `json:"contract"`
	DerivedAt string            `json:"derived_at"`
}

// secretFieldAmong returns the first of names the template declares secret, or
// "" if the provider considers all of them non-secret. An unknown field name is
// not secret by omission — it simply will not resolve.
func secretFieldAmong(tpl *template.Template, names []string) string {
	for _, n := range names {
		if spec, ok := tpl.Credential.Fields[n]; ok && spec.Secret {
			return n
		}
	}
	return ""
}

// handleLabelDelete removes a name binding (and its profile row).
//
// Gated as a `bind`: this is the inverse of pointing a name at a secret, so an
// operator who has locked down who may rebind credentials has locked down who
// may unbind them too — otherwise "you cannot repoint aws:prod" would coexist
// with "anyone may delete aws:prod", which is not a coherent control.
//
// Unbinding is evaluated at CRITICAL risk regardless of what binding would
// score, because losing the only name for a credential is how a vaulted secret
// becomes unreachable. The secret is not destroyed here (see Vault.DeleteLabel),
// but a name is the only handle callers have.
func (s *Server) handleLabelDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		// Preview resolves and reports what removal would affect, without
		// removing anything.
		//
		// It exists because the obvious way to build that confirmation — look
		// the label up with /credential/retrieve — is a CREDENTIAL READ: that endpoint
		// decrypts and returns the raw secret, gated as `assume`. Asking "what
		// am I about to detach?" must not decrypt the thing being detached.
		Preview bool `json:"preview,omitempty"`
		// DestroyEscrowedOriginal acknowledges, for an escrow label whose file
		// on disk is still a stub, that removal makes the original
		// unrecoverable. Named rather than a generic --yes on purpose: this is
		// the one label removal that destroys data, and the confirmation the
		// user gives has to be about THAT, not about labels in general.
		DestroyEscrowedOriginal bool `json:"destroy_escrowed_original,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	// Resolve first so the gate can evaluate every alias this token answers to,
	// the same way authorizeBind does — but hold the lookup error until after
	// authorization, so a denied caller cannot probe which labels exist.
	token, lookupErr := s.vlt.GetLabel(req.Name)

	c := callerForEndpoint(r, "akasha-bind", "akasha_bind")

	// The unbind half of the escrow gate. Prefix-only, so it answers the same
	// way for a label that exists and one that does not, and reveals nothing.
	if !isHuman(r) && escrowName(req.Name) {
		s.denyEscrow(w, "unbind", req.Name, token, c)
		return
	}

	// And the same rule /label/set enforces, because DELETE plus CREATE is a
	// re-point spelled in two commands.
	//
	// Refusing to re-point while leaving delete open closed nothing at all:
	// `akasha label rm github:default --yes` followed by `akasha put
	// github:default` moved the name onto an agent's own token, through the
	// shipped CLI, in the ordinary agent session. The guard has to cover every
	// way a name stops meaning what it meant, not the one that reads like
	// re-pointing.
	//
	// NO provisioning exemption here, unlike the bind side.
	//
	// One was added on the reasoning that "discovery prunes labels whose
	// credentials are gone". That reasoning was wrong on the facts: discovery
	// prunes through /vault/purge, and this endpoint has exactly one caller in
	// the tree — `akasha label rm`, which the human types. So the exemption had
	// no legitimate user and existed only as a hole, and because the id is
	// DECLARED rather than authenticated, one extra JSON field reopened the
	// bypass this guard was written to close:
	//
	//	POST /label/delete {"name":"github:default","agent_id":"akasha-discover"}
	//	POST /put          {"label":"github:default","fields":{"token":"…"}}
	//
	// An exemption is only worth its risk where something real needs it. This
	// one did not, so it is gone rather than narrowed.
	if !isHuman(r) && lookupErr == nil && token != "" {
		msg := fmt.Sprintf("%q is an existing name, and removing one is something only the person at the "+
			"keyboard does — deleting a name and creating it again is how a credential quietly changes "+
			"hands. If you vaulted something of your own, remove the name you chose for it.", req.Name)
		s.auditL.Emit(audit.Event{
			Token:          token,
			Action:         audit.ActionDenied,
			Risk:           "critical",
			AgentID:        c.agentID,
			IdentitySource: c.agentSrc.String(),
			ToolName:       c.tool,
			Task:           msg,
		})
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	names, aliasErr := s.aliasNames(req.Name, token)
	if aliasErr != nil {
		http.Error(w, "cannot determine which credentials this token is bound to — retry, and check the vault is readable with `akasha status`", http.StatusInternalServerError)
		return
	}
	for _, n := range names {
		provider, instance := splitLabel(n)
		polReq := c.policyReq("bind")
		polReq.Provider, polReq.Instance = provider, instance
		polReq.Category, polReq.Risk, polReq.Token = "Credential", "critical", token
		if !s.authorize(w, polReq) {
			return
		}
	}
	if lookupErr != nil {
		http.Error(w, fmt.Sprintf("no label named %q", req.Name), http.StatusNotFound)
		return
	}

	// Sibling names, so a caller can tell "detaching one of several handles"
	// from "cutting the last one". Names are not secrets; values are.
	siblings := append([]string{}, names[1:]...)
	sort.Strings(siblings)

	// Sibling names do not soften this: `akasha restore` resolves the escrow
	// label specifically, so a second alias on the same token keeps the bytes
	// reachable by hand while the file itself stays unrestorable.
	escrowPath, onlyCopy := s.escrowOnlyCopy(req.Name, token)

	if req.Preview {
		jsonOK(w, map[string]interface{}{
			"name": req.Name, "also_named": siblings,
			// So `akasha label rm` can warn about the right thing. Its generic
			// "re-run `akasha discover` to re-create it from disk" is actively
			// wrong here: what is on disk is not that file.
			"escrow_only_copy": onlyCopy, "escrow_path": escrowPath,
		})
		return
	}

	// Removing an escrow label whose original is not back on disk is not a name
	// cleanup, it is deletion of the user's file: the vault entry is the only
	// remaining copy of the original, and nothing can reach it once its name is
	// gone. Refuse and name the reversal, which costs nothing — restore first,
	// then the label is just a name again.
	if onlyCopy && !req.DestroyEscrowedOriginal {
		http.Error(w, fmt.Sprintf("%q is the only name for the escrowed original of %s, and what is on disk "+
			"there is not that file — removing this name would destroy it. Put it back first with "+
			"`akasha restore %s`, after which removing the label loses nothing. If you do not want the "+
			"escrowed bytes back — the directory is gone, or what is at that path now is the copy you mean "+
			"to keep — say so explicitly: `akasha label rm --destroy-escrowed-original %s`.",
			req.Name, escrowPath, escrowPath, req.Name), http.StatusConflict)
		return
	}

	if _, err := s.vlt.DeleteLabel(req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditL.Emit(audit.Event{
		Token:          token,
		Action:         audit.ActionUnbound,
		Category:       "Credential",
		Risk:           "critical",
		AgentID:        c.agentID,
		IdentitySource: c.agentSrc.String(),
		ToolName:       c.tool,
		Task:           unbindTask(req.Name, onlyCopy, escrowPath),
	})
	jsonOK(w, map[string]string{"status": "ok", "removed": req.Name})
}

// escrowOnlyCopy reports whether unbinding or re-pointing name would strand an
// escrowed original: the label is in the escrow namespace, and the entry it
// currently points at has no copy at the path it names, so the vault holds the
// last copy of that file anywhere. Returns the path either way, for the message.
//
// token is the entry the name resolves to TODAY — the one about to lose its
// only handle — not whatever is being bound in its place.
//
// It answers by comparing the escrowed bytes with what is on disk, and it fails
// closed on anything it cannot compare (an unreadable entry, a value that is
// not an envelope for this path). The question is "may I destroy this file",
// and the cost of a wrong "yes" is the file; the cost of a wrong "no" is one
// `akasha restore`, or the named override that already exists for the case
// where the file is genuinely unwanted.
func (s *Server) escrowOnlyCopy(name, token string) (string, bool) {
	if !escrowName(name) {
		return "", false
	}
	path := strings.TrimPrefix(name, escrow.LabelPrefix)
	if token == "" {
		return path, true
	}
	// An escrow-SHAPED name over an entry that is not an escrowed file — an
	// `akasha put escrow:...` that was allowed because the file was on disk at
	// the time — holds no original to strand, and saying it does would send the
	// user to `--destroy-escrowed-original` to clean up a name. The category is
	// written at Store time and never edited, and re-pointing an escrow label
	// away from a real envelope is what the guard above refuses, so this cannot
	// be arranged for a name that does hold one.
	if !s.escrowToken(token) {
		return path, false
	}
	// Peek, not Retrieve: this is the daemon comparing an entry with the disk
	// to answer a yes/no question, and nothing leaves the vault, so it must not
	// register as one more read of the user's escrowed file.
	blob, err := s.vlt.Peek(token)
	if err != nil {
		return path, true
	}
	return path, !escrow.RestoredOnDisk(blob, path)
}

// escrowEnvelopeFor reports whether token holds an escrow envelope for exactly
// this path — that is, whether the bind about to happen is `akasha protect`
// re-escrowing the same file.
//
// It is the one legitimate re-point of an escrow label, and it strands nothing:
// protect has just read the file and vaulted its current bytes, so the new
// entry IS the copy the old one is being replaced by. Everything else that
// re-points an escrow name — `akasha put escrow:<path>` above all — replaces
// the only handle on the user's file with something that is not that file.
func (s *Server) escrowEnvelopeFor(token, path string) bool {
	if token == "" || !s.escrowToken(token) {
		return false
	}
	blob, err := s.vlt.Peek(token)
	if err != nil {
		return false
	}
	var env escrow.Envelope
	return json.Unmarshal([]byte(blob), &env) == nil && env.Path == path
}

// unbindTask renders the audit line for a removed label, saying plainly when
// the removal took an escrowed original with it. That case is the only one
// where UNBOUND is data loss, so it must not read like the routine one.
func unbindTask(name string, destroyedEscrow bool, path string) string {
	if destroyedEscrow {
		return fmt.Sprintf("Removed label %q — the escrowed original of %s is now unrecoverable "+
			"(--destroy-escrowed-original)", name, path)
	}
	return fmt.Sprintf("Removed label %q (the secret itself was not deleted)", name)
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
	// Human-only, like every other deletion. An agent had a primitive the person
	// at the keyboard does not even have a command for: `/vault/purge` answered
	// 200 to an agent key out of the box, and no `akasha purge` exists. Nothing
	// an agent legitimately does needs to collect the human's garbage.
	if !isHuman(r) {
		http.Error(w, "collecting orphaned credential entries is done by the person at the keyboard; "+
			"it runs automatically after `akasha discover`", http.StatusForbidden)
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
		// Declared, not authenticated — see isFirstPartyProvisioning. It says
		// which of akasha's own paths is speaking, so re-vaulting a credential
		// discovery just re-read is not mistaken for an agent seizing a name.
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Token == "" {
		http.Error(w, "name and token required", http.StatusBadRequest)
		return
	}
	if !s.authorizeBind(w, r, req.Name, req.Token, req.AgentID) {
		return
	}
	if err := s.vlt.SetLabel(req.Name, req.Token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// handleCredentialRetrieve RESOLVES A NAME AND RETURNS THE DECRYPTED SECRET.
//
// It is not a metadata lookup, and the name says so now because the old one
// (/label/get) did not: it reads like "look up what this label points at", and
// that is exactly how it gets misused. Building `akasha label rm`, the obvious
// way to show a user what they were about to detach was to resolve the label
// here — which decrypted an SSH private key to answer a question about a name.
//
// If you want the token or the aliases without the value, you want
// /label/delete's preview mode (metadata only) or /inspect. If you want the
// value, this is the endpoint, and it is gated as `assume` accordingly.
func (s *Server) handleCredentialRetrieve(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	// Policy gate: credential/retrieve hands back the raw value, so it is the same
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
	// An escrowed file has no brokered form: its value IS the plaintext its
	// owner removed from disk, so this endpoint is a raw READ for it whatever
	// verb it is gated under. Human only — see the escrow-namespace note above.
	if !isHuman(r) && (escrowName(name) || s.escrowToken(token)) {
		s.denyEscrow(w, "read", name, token, c)
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
		// Say what left the vault. "Assume label" described the GATE this path
		// is evaluated under, not the outcome — and an assume hands back a file
		// path, while this hands back the secret itself. A reviewer scanning
		// the log for disclosures has to be able to see one here.
		Task: fmt.Sprintf("Returned the decrypted value for %q", name),
	})
	jsonOK(w, map[string]string{"value": value})
}

// availableHint lists the vaulted instances for a provider, so a failed
// lookup tells the caller (often an agent that guessed or typo'd a profile)
// what would resolve. Instance names are not secrets — only their values are.
func (s *Server) availableHint(provider string) string {
	labels, err := s.vlt.ListLabels(provider + ":")
	if err != nil || len(labels) == 0 {
		// `escrow:` is not a provider anyone puts to. The generic advice below
		// renders for it as `akasha put escrow:<name>`, which is the one
		// command that re-points an escrow label away from the file it is the
		// only handle on — advice that ends in permanent data loss, offered at
		// the moment a user is already looking for a file they cannot find.
		if isEscrowProvider(provider) {
			return "nothing is escrowed (escrow entries are created by `akasha protect <path>`, never by `akasha put`)"
		}
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
	// Escrow labels are absolute paths to the credential files their owner took
	// off disk — a target list, and the first request of the read chain the
	// escrow gate closes. An agent has no use for them: they are not assumable
	// (vault_status was in fact advertising them as if they were), and every
	// path that consumes one runs as the human. Filter rather than 403, so a
	// bare `list` still works from inside an agent session.
	if !isHuman(r) {
		kept := names[:0]
		for _, n := range names {
			if !escrowName(n) {
				kept = append(kept, n)
			}
		}
		names = kept
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
	// And the values, which /store checks and this endpoint did not — the more
	// damaging half of the same hole. A value /store accepts sits beside the
	// real entry under a token nobody uses; /put ends in SetLabel, so a value
	// accepted here becomes what the NAME resolves to, and every later assume,
	// git push and credential_process follows it. An agent that answered "my
	// AWS calls fail" by putting made-up keys under aws:default orphaned the
	// user's real credential and reported success — a label that resolves is
	// indistinguishable from a label that works until something authenticates.
	//
	// Human-exempt for the same reason /store is: `akasha discover` and
	// `akasha put` carry whatever is actually in the user's config, including
	// the deliberately unreal keys a LocalStack or MinIO setup uses.
	if !isHuman(r) {
		if err := checkPutFields(req.Label, req.Fields); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if !s.authorizeBind(w, r, req.Label, "", "") {
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

// checkPutFields rejects a credential map that cannot be the credential its
// label claims. It asks the two questions checkStoredValue asks of a single
// value — is this a placeholder, does it have the form its category requires —
// and the one only /put can ask: can the provider the label names actually use
// this map? A map bound to `aws:default` with no access_key_id in it is not a
// credential; it is a name that every later `assume` falls into.
//
// The category comes from the FIELD NAME, because a credential map carries
// none. A field Akasha has no opinion about is checked for size and
// placeholders only, so an `env:` label full of arbitrary secrets still works.
func checkPutFields(label string, fields map[string]string) error {
	names := make([]string, 0, len(fields))
	for f := range fields {
		names = append(names, f)
	}
	sort.Strings(names) // so the same bad map always reads the same way

	for _, field := range names {
		value := fields[field]
		if len(value) > maxAgentSecretBytes {
			return fmt.Errorf("field %q is %d bytes — that is a file, not a credential. "+
				"To take a credential FILE off disk, the person at the keyboard runs `akasha protect <path>`",
				field, len(value))
		}
		if classifier.LooksFabricated(value) {
			return fmt.Errorf("field %q is a placeholder, not a credential — putting it under %q would "+
				"leave that name resolving to a value nothing can authenticate with. If you do not have "+
				"the secret, do not invent one: call vault_status to see what is already vaulted, then "+
				"vault_assume(provider, profile) to USE it", field, label)
		}
		// Canonicalise through the template's aliases first: `value` is an alias
		// for `token` on every git-family provider, and judging the key as
		// written let {"value": "junk"} past a check that had an opinion about
		// `token`. ResolveCreds maps it back either way, so the guard has to
		// look at the same name the delivery path will.
		fieldProvider, _ := splitLabel(label)
		canonical := field
		if tpl := template.Get(fieldProvider); tpl != nil {
			canonical = tpl.CanonicalField(field)
		}
		category, known := classifier.CategoryForField(fieldProvider, canonical)
		if !known {
			continue
		}
		if shape, ok := classifier.ShapeFor(category); ok && !shape.Re.MatchString(strings.TrimSpace(value)) {
			return fmt.Errorf("field %q is not a %s — a %s is %s. If you do not have the real value, do "+
				"not invent one: call vault_status to see what is already vaulted, then "+
				"vault_assume(provider, profile) to USE it", field, category, category, shape.Want)
		}
	}

	// The map as a whole. Field-by-field checks catch a value that is the wrong
	// SHAPE; this catches the map that is the wrong credential entirely — the
	// {"k":"v"} an agent writes under aws:default when it has nothing to put
	// there. Only providers this daemon knows are checked, so `env:` labels and
	// unknown providers are unaffected.
	provider, _ := splitLabel(label)
	if tpl := template.Get(provider); tpl != nil {
		if _, err := tpl.ResolveCreds(fields); err != nil {
			return fmt.Errorf("%v — so binding this map to %q would leave a name that no %s command "+
				"can use. If you do not have the credential, call vault_status to see what is already "+
				"vaulted, then vault_assume(provider, profile) to USE it", err, label, provider)
		}
	}
	return nil
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
		http.Error(w, missingProviderProfile("vault_assume"), http.StatusBadRequest)
		return
	}

	tpl := template.Get(req.Provider)

	// A provider that does not exist is a 404, and it has to be answered BEFORE
	// the raw-secret gate below. The two used to share a branch, because
	// `tpl == nil` means both "no such provider" and the generic env: provider
	// — so a caller that guessed `provider: "s3"` was told S3's credential
	// would come back as a raw secret, that it had a credential helper, and
	// that vault_retrieve would hand over the value. All three are false, and
	// the last one points at the raw-secret tool for a credential that is not
	// there. Naming the providers that DO exist is not a disclosure: /label/list
	// and vault_status already hand an agent the assumable provider:instance map.
	if tpl == nil && !assume.Supported(req.Provider) {
		http.Error(w, fmt.Sprintf("unknown provider %q — this machine has: %s. Call vault_status for the "+
			"provider/profile pairs that exist, then retry with one of them.",
			req.Provider, strings.Join(assume.SupportedProviders(), ", ")), http.StatusNotFound)
		return
	}

	// An agent must never receive a raw secret in an env var: that lands the
	// credential in its context, defeating assume's "use it without seeing it"
	// contract. Only the local human CLI, in its own trusted shell, may take
	// this path.
	//
	// The condition is written as "not the human" rather than "is a verified
	// agent" on purpose. The latter was satisfied by presenting a valid key, so
	// an agent bypassed it by presenting NO key and being mistaken for the
	// human — including an agent whose key had just been revoked, which is how
	// `agent revoke` came to hand out more access than it took away. Requiring
	// an affirmative CLI identity means an unrecognised caller is refused
	// instead of promoted.
	//
	// This covers providers whose env delivery materializes a secret field
	// (github/git, source-brokered) and the generic env: provider (tpl == nil,
	// always raw); file-delivered providers (aws/ssh) return a PATH and are exempt.
	if !isHuman(r) && (tpl == nil || tpl.DeliversSecretEnv()) {
		// No vault_retrieve here. The old text ended by offering it "if you
		// explicitly need the value" — pointing the caller at the raw-secret
		// tool at the exact moment the daemon had decided it must not have the
		// raw secret, and inviting it to route around the refusal. What it can
		// legitimately do instead is USE the credential without seeing it, so
		// that is what the message says, in the one form that survives a shell
		// which does not keep environment between calls.
		http.Error(w, fmt.Sprintf("provider %q can't be assumed by an agent — its credential is a raw secret, "+
			"and assume would deliver it into your context. Run the command through akasha instead, which "+
			"brokers the secret per operation and never shows it to you:\n"+
			"  akasha exec --assume %s:%s -- <your command>\n"+
			"Or work in a session prepared by `akasha setup`, where the provider's own tooling resolves "+
			"through `akasha helper %s` on every use.",
			req.Provider, req.Provider, req.Profile, req.Provider), http.StatusForbidden)
		return
	}

	c := callerForEndpoint(r, "akasha-assume", "akasha_assume")

	resolved, err := s.credsFor(r.Context(), "assume", req.Provider, req.Profile, c)
	if err != nil {
		status := credsErrStatus(err)
		// A policy that refuses `assume` for a provider with a per-operation
		// route is not saying "no", it is saying "use the other door" — and
		// until now the daemon rendered it as "no". The operator writes the
		// rule the starter policy itself suggests, runs start failing with what
		// reads as a broken product, and the cheapest fix available to both the
		// human and the model is deleting the rule. That is how hardening gets
		// switched off.
		//
		// Naming the recovery is settled practice here: the raw-secret refusal
		// fourteen lines above does it, and its comment records that the older
		// text was actively harmful because it pointed at the wrong one.
		if status == http.StatusForbidden && tpl.Brokerable() {
			http.Error(w, fmt.Sprintf("%v\n"+
				"This provider can still be used WITHOUT handing over the credential — policy is "+
				"refusing the session handover, not the use. Broker it per operation instead:\n"+
				"  akasha exec --assume %s:%s -- <your command>\n"+
				"That resolves the secret on each call through `akasha helper %s`, materializes "+
				"nothing, and records every use separately.",
				err, req.Provider, req.Profile, req.Provider), status)
			return
		}
		http.Error(w, err.Error(), status)
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

	// Bound the lifetime before materializing anything. ttl_seconds is an
	// advertised MCP parameter, so the caller choosing it is routinely the
	// model; unbounded, it wrote a plaintext credential file whose mtime the
	// sweeper would never reach. See internal/assume/ttl.go.
	var deadline time.Time
	if run := runFrom(r); run != nil {
		deadline = run.Deadline
	}
	grant := assume.ClampTTL(time.Duration(req.TTLSeconds)*time.Second,
		c.assumeCaller(deadline), time.Now())
	if grant.TTL <= 0 {
		// Only reachable inside a run whose deadline has already passed. Its
		// key is normally revoked by then; refusing here means a credential can
		// never be materialized with a lifetime of zero, which would otherwise
		// be swept immediately and read as an unexplained failure.
		http.Error(w, "this run has ended; start a new one before assuming a credential",
			http.StatusForbidden)
		return
	}

	result, err := assume.Write(req.Provider, req.Profile, resolved, grant.TTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Say what was actually granted, always, and why it was shortened when it
	// was. A silent clamp leaves a caller planning around a lifetime it does not
	// have, and the file really does vanish at the earlier time.
	result.GrantedTTLSeconds = int(grant.TTL.Seconds())
	result.TTLNotice = grant.Reason
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
	//
	// Escrow is the exception to the paragraph above, because it is not a
	// broker at all: there is no per-operation use of "the bytes of a file", so
	// an escrow entry reached through here would just be the raw file. It does
	// not parse as a credential map today (a 500, not a disclosure), but that is
	// an accident of the envelope's shape, and the guard should not depend on it.
	helper := callerForEndpoint(r, "akasha-helper", "akasha_helper")
	if !isHuman(r) && isEscrowProvider(provider) {
		s.denyEscrow(w, "broker", provider+":"+instance, "", helper)
		return
	}
	creds, err := s.credsFor(r.Context(), "broker", provider, instance, helper)
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
// onlyFields (optional) restricts which credential fields are decrypted. It is
// a security control, not an optimisation: a caller that needs one non-secret
// field must not cause the whole credential to be unwrapped in memory. It
// applies to the vault path only — a source backend returns whatever it returns
// — so callers that must not touch secrets refuse source-backed providers
// outright rather than filtering after the fact.
func (s *Server) credsFor(ctx context.Context, action, provider, instance string, c caller, onlyFields ...string) (map[string]string, error) {
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
			RunID:          c.runID,
			Action:         audit.ActionDenied,
			Category:       "Credential",
			Risk:           riskOfAction(action),
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
		// onlyFields, when set, is the caller declaring it needs a subset —
		// DESCRIBE asks for the one non-secret field its contract reads, so the
		// secret half of the credential is never decrypted at all. Skipping the
		// Retrieve (rather than filtering afterwards) is the point: the value
		// never exists in this process, and its retrieved_count does not move.
		if len(onlyFields) > 0 && !slices.Contains(onlyFields, field) {
			continue
		}
		val, err := s.vlt.Retrieve(tok, tool)
		if err != nil {
			return nil, &statusError{http.StatusInternalServerError, fmt.Errorf("retrieve %s: %w", field, err)}
		}
		resolved[field] = val
	}
	s.auditL.Emit(audit.Event{
		RunID:          c.runID,
		Token:          mapToken,
		Action:         audit.ActionRetrieved,
		Category:       "Credential",
		Risk:           riskOfAction(action),
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
	switch action {
	case "broker":
		return fmt.Sprintf("Brokered %s:%s for one operation (helper)", provider, instance)
	case "describe":
		// A describe decrypts the credential but vends nothing. Saying "Assume"
		// here would overstate what happened in the one record a reviewer reads.
		return fmt.Sprintf("Decrypted %s:%s in-process to derive non-secret identity facts (nothing vended)", provider, instance)
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
