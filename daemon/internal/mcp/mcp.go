// Package mcp implements a Model Context Protocol server over stdio.
//
// It is a thin JSON-RPC 2.0 proxy: every MCP tools/call translates into
// an HTTP request against the already-running Akasha daemon on
// 127.0.0.1:7743. The daemon is the single source of truth — this process
// never opens the vault directly.
//
// Usage:
//
//	AKASHA_AGENT_KEY=agt_... akasha mcp --agent-id claude-code
//
// Claude Code config:
//
//	{ "mcpServers": { "akasha": {
//	    "command": "akasha",
//	    "args": ["mcp", "--agent-id", "claude-code"],
//	    "env": { "AKASHA_AGENT_KEY": "agt_..." }
//	}}}
//
// The key travels in the environment because argv is world-readable: a key on
// the command line is legible to anything that can run `ps`, which includes
// every other agent on the machine.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	protocolVersion = "2024-11-05"
	serverName      = "akasha"
	serverVersion   = "1.0.0"
	defaultBase     = "http://127.0.0.1:7743"
)

// ─── JSON-RPC 2.0 types ───────────────────────────────────────────────────

type Request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ─── MCP tool result types ────────────────────────────────────────────────

type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string) ToolResult {
	return ToolResult{Content: []ContentBlock{{Type: "text", Text: text}}}
}

func errorResult(msg string) ToolResult {
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

// ─── Server ───────────────────────────────────────────────────────────────

type Server struct {
	agentID    string
	apiKey     string
	daemonBase string
	client     *http.Client
}

func newServer(agentID, apiKey, daemonBase string) *Server {
	return &Server{
		agentID:    agentID,
		apiKey:     apiKey,
		daemonBase: daemonBase,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// NewServerForTest builds a Server with a custom daemon base URL.
// Only used by tests — production code uses Run().
func NewServerForTest(agentID, apiKey, daemonBase string) *Server {
	return newServer(agentID, apiKey, daemonBase)
}

// Run is the entry point called from the Cobra command.
// It reads from os.Stdin and writes to os.Stdout.
func Run(agentID, apiKey string) error {
	log.SetOutput(os.Stderr) // all diagnostics to stderr, never stdout
	log.Printf("akasha mcp: starting (agent=%s daemon=%s)", agentID, defaultBase)
	s := newServer(agentID, apiKey, defaultBase)
	s.Serve(os.Stdin, os.Stdout)
	return nil
}

// Serve runs the JSON-RPC message loop, reading from in and writing to out.
// Exported so tests can drive it with pipes instead of os.Stdin/Stdout.
func (s *Server) Serve(in io.Reader, out io.Writer) {
	enc := json.NewEncoder(out)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1 MB max line

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			enc.Encode(Response{
				JSONRPC: "2.0",
				Error:   &RPCError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			continue
		}

		// Notifications have no id — no response required.
		if req.ID == nil {
			s.handleNotification(req)
			continue
		}

		resp := s.dispatch(req)
		enc.Encode(resp)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Printf("akasha mcp: scanner error: %v", err)
	}
}

// ─── Dispatch ─────────────────────────────────────────────────────────────

func (s *Server) dispatch(req Request) (resp Response) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("akasha mcp: panic in handler: %v", r)
			resp = Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32603, Message: fmt.Sprintf("internal error: %v", r)},
			}
		}
	}()

	resp.JSONRPC = "2.0"
	resp.ID = req.ID

	switch req.Method {
	case "initialize":
		resp.Result = s.handleInitialize()

	case "tools/list":
		resp.Result = map[string]interface{}{"tools": toolCatalog()}

	case "tools/call":
		var p CallParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &RPCError{Code: -32600, Message: "invalid params: " + err.Error()}
			return
		}
		result := s.callTool(p.Name, p.Arguments)
		resp.Result = result

	case "ping":
		resp.Result = map[string]interface{}{}

	default:
		resp.Error = &RPCError{Code: -32601, Message: "method not found: " + req.Method}
	}

	return
}

func (s *Server) handleNotification(req Request) {
	log.Printf("akasha mcp: notification: %s", req.Method)
	// initialized, cancelled, etc. — no response needed.
}

func (s *Server) handleInitialize() interface{} {
	return map[string]interface{}{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
		"serverInfo": map[string]interface{}{
			"name":    serverName,
			"version": serverVersion,
		},
	}
}

// ─── Tool dispatch ────────────────────────────────────────────────────────

func (s *Server) callTool(name string, args map[string]interface{}) ToolResult {
	switch name {
	case "vault_wrap":
		return s.callWrap(args)
	case "vault_store":
		return s.callStore(args)
	case "vault_retrieve":
		return s.callRetrieve(args)
	case "vault_grant":
		return s.callGrant(args)
	case "vault_inspect":
		return s.callInspect(args)
	case "vault_identity":
		return s.callIdentity(args)
	case "vault_put":
		return s.callPut(args)
	case "vault_assume":
		return s.callAssume(args)
	case "vault_status":
		return s.callStatus()
	default:
		return errorResult("unknown tool: " + name)
	}
}

// ─── Tool handlers ────────────────────────────────────────────────────────

func (s *Server) callWrap(args map[string]interface{}) ToolResult {
	payload := copyArgs(args)
	payload["agent_id"] = s.agentID
	body, status, err := s.daemonPost("/wrap", payload)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("vault error (%d): %s", status, body))
	}
	return textResult(string(body))
}

func (s *Server) callStore(args map[string]interface{}) ToolResult {
	payload := copyArgs(args)
	payload["agent_id"] = s.agentID
	body, status, err := s.daemonPost("/store", payload)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("vault error (%d): %s", status, body))
	}
	return textResult(string(body))
}

func (s *Server) callRetrieve(args map[string]interface{}) ToolResult {
	payload := copyArgs(args)
	payload["agent_id"] = s.agentID
	body, status, err := s.daemonPost("/retrieve", payload)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("vault error (%d): %s%s", status, body, tokenHelp(string(body))))
	}
	return textResult(string(body))
}

func (s *Server) callGrant(args map[string]interface{}) ToolResult {
	payload := copyArgs(args)
	payload["grantor_agent"] = s.agentID
	body, status, err := s.daemonPost("/grant", payload)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	// vault_grant takes a token too, so it fails the same way and for the same
	// reason: a caller that was never handed one invents it. "cannot grant
	// unknown token: token not found" was the one member of that error class
	// left undecorated.
	if status >= 400 {
		return errorResult(fmt.Sprintf("vault error (%d): %s%s", status, body, tokenHelp(string(body))))
	}
	return textResult(string(body))
}

func (s *Server) callInspect(args map[string]interface{}) ToolResult {
	token, _ := args["token"].(string)
	grantID, _ := args["grant_id"].(string)

	var path string
	if token != "" {
		path = "/inspect?token=" + url.QueryEscape(token)
	} else if grantID != "" {
		path = "/inspect?grant_id=" + url.QueryEscape(grantID)
	} else {
		return errorResult("token or grant_id required" + vaultTokenRecovery)
	}

	body, status, err := s.daemonGet(path)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("vault error (%d): %s%s", status, body, tokenHelp(string(body))))
	}
	return textResult(string(body))
}

// vaultTokenRecovery is appended to every failure of the two token-taking
// tools. It exists because "token not found" — by a wide margin the most
// produced error on this surface — named no next step, and a caller with no
// token has no way to construct one.
//
// What a model does with an error that names no recovery is invent: measured
// over 19 such errors, 32% of the next actions were calls to a tool that does
// not exist (vault_show, vault_login, vault_authenticate) and only 16% found
// vault_status. With the recovery named, invented tools went to zero and
// vault_status doubled. The wording is therefore load-bearing, not decoration:
// it has to say that the token cannot be guessed, and name the tool that
// answers the question the caller actually had.
const vaultTokenRecovery = "\n\n" +
	"A vault:// token is issued by vault_wrap or vault_store — it cannot be guessed, and it cannot be " +
	"built out of a field name. You will only have one if an earlier tool call gave it to you.\n" +
	"What you probably want instead:\n" +
	"  • to USE a credential: vault_assume(provider, profile) — e.g. provider=\"aws\", profile=\"default\"\n" +
	"  • to know WHICH ACCOUNT it belongs to: vault_identity(provider, profile)\n" +
	"Call vault_status first: it lists every provider/profile pair on this machine."

// tokenHelp decides whether a daemon error is about the TOKEN rather than
// about permission, and appends the recovery when it is.
//
// It matches on the daemon's text because that is what a JSON-RPC proxy has:
// /retrieve and /inspect answer with plain http.Error bodies, and the same 403
// covers a policy denial, an escrow refusal and a bad token. Telling a caller
// that was denied by policy to "call vault_status and try vault_assume" would
// be teaching it to retry a decision, so the appended text is earned by the
// specific vault-layer phrasings and nothing else. Every phrase below is pinned
// by TestTokenErrorWordingTheMCPLayerMatches in internal/server, so a reworded
// error cannot silently drop the help.
func tokenHelp(body string) string {
	for _, phrase := range []string{"token not found", "invalid token format", "token expired", "token or grant_id required"} {
		if strings.Contains(body, phrase) {
			return vaultTokenRecovery
		}
	}
	return ""
}

// missingProviderProfile is the same message the daemon gives, produced here
// for the calls that never reach it. It names the format because the mistake it
// answers is a format mistake: a caller that has seen the label `aws:default`
// written anywhere passes it as one argument — as `provider`, or as a `label`
// this schema does not have — and a refusal that repeats "provider and profile
// required" without saying what those look like leaves it no way to correct.
// Missing arguments were 7 of the 21 failed first calls measured on this
// surface; naming the recovery is what took follow-up tool invention to zero.
func missingProviderProfile(tool string) ToolResult {
	return errorResult(fmt.Sprintf("provider and profile required — %s takes them as two separate "+
		"arguments, e.g. provider=\"aws\", profile=\"default\". A single \"aws:default\" label is not one "+
		"of them; if that is what you have, split it on the colon. Call vault_status first: it lists "+
		"every provider/profile pair on this machine.", tool))
}

func (s *Server) callIdentity(args map[string]interface{}) ToolResult {
	provider, _ := args["provider"].(string)
	profile, _ := args["profile"].(string)
	if provider == "" || profile == "" {
		return missingProviderProfile("vault_identity")
	}
	body, status, err := s.daemonGet(fmt.Sprintf("/identity?provider=%s&profile=%s",
		url.QueryEscape(provider), url.QueryEscape(profile)))
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("identity error (%d): %s", status, body))
	}
	return textResult(string(body))
}

func (s *Server) callPut(args map[string]interface{}) ToolResult {
	payload := copyArgs(args)
	body, status, err := s.daemonPost("/put", payload)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("put error (%d): %s", status, body))
	}
	return textResult(string(body))
}

func (s *Server) callAssume(args map[string]interface{}) ToolResult {
	provider, _ := args["provider"].(string)
	profile, _ := args["profile"].(string)
	if provider == "" || profile == "" {
		return missingProviderProfile("vault_assume")
	}
	payload := copyArgs(args)
	body, status, err := s.daemonPost("/assume", payload)
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("assume error (%d): %s", status, body))
	}
	return textResult(string(body))
}

func (s *Server) callStatus() ToolResult {
	body, status, err := s.daemonGet("/health")
	if err != nil {
		return errorResult(daemonErr(err))
	}
	if status >= 400 {
		return errorResult(fmt.Sprintf("daemon error (%d): %s", status, body))
	}

	// Merge in the assumable credentials, grouped by provider, so one status
	// call tells an agent exactly which provider/profile pairs vault_assume
	// accepts — instead of leaving it to guess (and 404) its way there.
	// Instance names are not secrets — only their values are.
	var health map[string]interface{}
	if json.Unmarshal(body, &health) != nil {
		return textResult(string(body))
	}
	if labelsBody, st, err := s.daemonGet("/label/list"); err == nil && st < 400 {
		var names []string
		if json.Unmarshal(labelsBody, &names) == nil {
			assumable := map[string][]string{}
			for _, n := range names {
				if i := strings.Index(n, ":"); i > 0 {
					assumable[n[:i]] = append(assumable[n[:i]], n[i+1:])
				}
			}
			health["assumable"] = assumable
		}
	}
	merged, err := json.Marshal(health)
	if err != nil {
		return textResult(string(body))
	}
	return textResult(string(merged))
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────

func (s *Server) daemonPost(path string, body interface{}) ([]byte, int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest("POST", s.daemonBase+path, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("X-Akasha-Key", s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

func (s *Server) daemonGet(path string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", s.daemonBase+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if s.apiKey != "" {
		req.Header.Set("X-Akasha-Key", s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

// ─── Tool catalog ─────────────────────────────────────────────────────────

func toolCatalog() []interface{} {
	return []interface{}{
		tool("vault_wrap",
			"Scan content for sensitive values and vault them. Returns clean content with vault:// tokens replacing any sensitive values found. Use this before sending content to any tool or storing it anywhere.",
			props(
				req("content", "string", "The content to scan for sensitive values"),
				req("tool_name", "string", "The tool that will use this content"),
				opt("task", "string", "What the agent is doing (recorded in audit log)"),
				opt("reasoning_trace", "string", "Why this tool call is happening (recorded in audit log)"),
				opt("triggered_by", "string", "What triggered this action"),
			),
			[]string{"content", "tool_name"},
		),
		tool("vault_store",
			"Store a secret YOU ALREADY HOLD directly in the vault, without classification. Use it when a value has been given to you and you know it is sensitive. Do NOT call it to solve a missing credential: storing a value you invented does not create a credential, it puts a decoy next to the real one — if a credential seems to be missing, call vault_status to see what is already vaulted and vault_assume to use it. Placeholders and values that do not have the form of the category you name are rejected.",
			props(
				req("content", "string", "The secret value to vault"),
				req("category", "string", "Category: AWSAccessKeyID, AWSSecretKey, APIKey, SSN, CreditCard, Password, etc."),
				req("risk", "string", "Risk level: critical, high, medium, or low"),
				opt("tool_name", "string", "Tool associated with this secret"),
				opt("task", "string", "What the agent is doing"),
			),
			[]string{"content", "category", "risk"},
		),
		tool("vault_retrieve",
			"Retrieve the real value for a vault:// token or redeem a grt:// grant. The value is decrypted and returned for use in a tool call. Every retrieval is logged with agent identity, tool name, and task. You will only have a token if an earlier tool call handed you one — a vault:// token cannot be guessed or built from a field name, so if you were not given one this is not the tool you want: use vault_assume to USE a credential, or vault_identity to ask which account it belongs to.",
			props(
				opt("token", "string", "vault:// token to retrieve directly"),
				opt("grant_id", "string", "grt:// grant token from an A2A task payload"),
				req("requesting_tool", "string", "The tool that will use the retrieved value"),
				opt("task", "string", "What the agent is doing (recorded in audit log)"),
				opt("reasoning_trace", "string", "Why this retrieval is happening"),
			),
			[]string{"requesting_tool"},
		),
		tool("vault_grant",
			"Create an A2A delegation grant. Allows another agent to retrieve a vault token for use with a specific tool. The grant ID travels in the A2A task payload — the real value never does.",
			props(
				req("token", "string", "vault:// token to delegate"),
				req("grantee_agent", "string", "Agent ID that will receive the grant"),
				opt("allowed_tool", "string", "Restrict grant to a specific tool name"),
				opt("task", "string", "Human-readable task description (recorded in audit log)"),
				opt("ttl_seconds", "number", "Seconds until grant expires (0 = no expiry)"),
			),
			[]string{"token", "grantee_agent"},
		),
		tool("vault_inspect",
			"Get metadata for a vault token or grant without decrypting the value. Returns category, risk level, agent ID, tool name, timestamps, and retrieval count. You will only have a token if an earlier tool call handed you one; if you were not given one, this is not the tool you want — call vault_status to see what exists.",
			props(
				opt("token", "string", "vault:// token to inspect"),
				opt("grant_id", "string", "grt:// grant to inspect"),
			),
			[]string{},
		),
		tool("vault_put",
			"Store a secret under a label so it can be assumed later — the simple way to vault a credential that discovery didn't find, including for providers vault_assume doesn't natively support. Use the 'env:<name>' label form for arbitrary secrets: the field names become environment variable names. Example: put {label:'env:stripe', fields:{STRIPE_API_KEY:'sk_live_...'}}, then vault_assume(provider='env', profile='stripe') exports STRIPE_API_KEY.",
			props(
				req("label", "string", "Label of the form provider:profile, e.g. 'env:stripe' or 'aws:prod'"),
				req("fields", "object", "Map of field name → secret value. For env: labels, field names become env var names."),
				opt("provider", "string", "Optional: provider for a structured profile row (defaults from label)"),
				opt("profile", "string", "Optional: profile name for a structured profile row"),
			),
			[]string{"label", "fields"},
		),
		tool("vault_assume",
			"Assume a file-delivered credential profile (e.g. aws, gcp, ssh) IN ORDER TO ACT with it. Akasha writes a short-lived, provider-native credentials FILE and returns env vars pointing at it — you NEVER receive the raw secret, only a path. Far safer than vault_retrieve. HOW TO USE THE RESULT: if your shell tool does not keep environment variables between calls — most, including Claude Code's Bash tool, do not — then setting the returned env vars and stopping accomplishes NOTHING: they are gone by your next command, which then silently authenticates with whatever plaintext is still on disk while the audit log records a brokered use that never happened. Do one of these instead, in a single shell call: run the returned 'run_via' command (`akasha exec --assume <provider>:<profile> -- <your command>`), or put the returned 'run_prefix' in front of your command. Never cat the returned path: that puts the raw secret into your context, which is the one thing this tool exists to prevent. If you only need to know WHICH ACCOUNT a credential belongs to, use vault_identity instead — it answers without a network call and keeps working when the keys are dead. NOTE: token providers whose credential is a plain env var (github, git) are NOT assumable this way — that would hand you the raw token; instead just run git in a session set up by `akasha setup`, and Akasha brokers the token per fetch/push via its credential helper. Call vault_status to see which profiles are assumable.",
			props(
				req("provider", "string", "Provider: aws, gcp, github, gitlab, or ssh"),
				req("profile", "string", "Profile name, e.g. 'default' for AWS or 'gitlab' for an SSH key"),
				opt("ttl_seconds", "number", "Seconds until the credential file is cleaned up (default 3600)"),
			),
			[]string{"provider", "profile"},
		),
		tool("vault_identity",
			"Ask WHICH ACCOUNT a vaulted credential belongs to — AWS account number, principal, key type — without assuming it, using it, or making any network call. Use this INSTEAD of vault_assume whenever the question is about identity rather than action ('what's my AWS account number?', 'which account does this profile point at?', 'am I about to act on prod?'). Returns only non-secret facts; it is structurally incapable of returning a credential. Because the facts are derived locally, this still answers for a credential whose keys have been deactivated or rotated — when calling the provider's API would just fail. Call vault_status for the provider/profile names.",
			props(
				req("provider", "string", "Provider, e.g. aws"),
				req("profile", "string", "Profile name, e.g. 'default'"),
			),
			[]string{"provider", "profile"},
		),
		tool("vault_status",
			"Check the Akasha daemon health and vault statistics, and list every assumable credential grouped by provider ('assumable': {provider: [profiles]}). Call this FIRST when you need a credential but aren't sure of the exact provider/profile names that vault_assume or vault_identity expect.",
			props(),
			[]string{},
		),
	}
}

// ─── Schema helpers ───────────────────────────────────────────────────────

func tool(name, desc string, properties map[string]interface{}, required []string) map[string]interface{} {
	return map[string]interface{}{
		"name":        name,
		"description": desc,
		"inputSchema": map[string]interface{}{
			"type":       "object",
			"properties": properties,
			"required":   required,
		},
	}
}

func props(fields ...map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	for _, f := range fields {
		for k, v := range f {
			m[k] = v
		}
	}
	return m
}

func req(name, typ, desc string) map[string]interface{} {
	return map[string]interface{}{
		name: map[string]interface{}{"type": typ, "description": desc},
	}
}

func opt(name, typ, desc string) map[string]interface{} {
	return map[string]interface{}{
		name: map[string]interface{}{"type": typ, "description": desc},
	}
}

// ─── Utilities ────────────────────────────────────────────────────────────

func copyArgs(args map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(args)+2)
	for k, v := range args {
		out[k] = v
	}
	return out
}

func daemonErr(err error) string {
	return fmt.Sprintf("daemon not reachable: %v — is 'akasha start' running on 127.0.0.1:7743?", err)
}
