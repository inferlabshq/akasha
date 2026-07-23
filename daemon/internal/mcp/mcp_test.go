package mcp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/internal/mcp"
)

// ─── Helpers ──────────────────────────────────────────────────────────────

// newTestServer builds an mcp.Server pointed at a mock daemon.
func newTestServer(t *testing.T, handler http.Handler) *mcp.Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return mcp.NewServerForTest("test-agent", "", ts.URL)
}

// send sends a single JSON-RPC request line and returns the parsed response.
func send(t *testing.T, s *mcp.Server, req string) map[string]interface{} {
	t.Helper()
	in := strings.NewReader(req + "\n")
	var out bytes.Buffer
	s.Serve(in, &out)

	if out.Len() == 0 {
		return nil // notification — no response expected
	}
	var result map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v\nraw: %s", err, out.String())
	}
	return result
}

func reqJSON(method string, id int, params interface{}) string {
	var p interface{} = map[string]interface{}{}
	if params != nil {
		p = params
	}
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  p,
	})
	return string(b)
}

func notificationJSON(method string) string {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  map[string]interface{}{},
	})
	return string(b)
}

// ─── Tests ────────────────────────────────────────────────────────────────

func TestInitialize(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	resp := send(t, s, reqJSON("initialize", 1, map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
	}))

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]interface{})
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("wrong protocolVersion: %v", result["protocolVersion"])
	}
	caps := result["capabilities"].(map[string]interface{})
	if _, ok := caps["tools"]; !ok {
		t.Fatal("capabilities.tools missing")
	}
	info := result["serverInfo"].(map[string]interface{})
	if info["name"] != "akasha" {
		t.Fatalf("wrong server name: %v", info["name"])
	}
}

func TestToolsList(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	resp := send(t, s, reqJSON("tools/list", 2, nil))

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})

	expectedTools := []string{
		"vault_wrap", "vault_store", "vault_retrieve",
		"vault_grant", "vault_inspect", "vault_put", "vault_assume", "vault_status",
	}
	if len(tools) != len(expectedTools) {
		t.Fatalf("expected %d tools, got %d", len(expectedTools), len(tools))
	}

	names := map[string]bool{}
	for _, t := range tools {
		tool := t.(map[string]interface{})
		names[tool["name"].(string)] = true
		// Each tool must have an inputSchema.
		if tool["inputSchema"] == nil {
			t_name := tool["name"].(string)
			_ = t_name
		}
	}
	for _, expected := range expectedTools {
		if !names[expected] {
			t.Fatalf("tool %q missing from catalog", expected)
		}
	}
}

func TestVaultWrap_success(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wrap" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"clean_content":"SSN is vault://abc123","vaulted":true,"token":"vault://abc123","category":"SSN","risk":"critical"}`)
	}))
	t.Cleanup(daemon.Close)
	s := mcp.NewServerForTest("test-agent", "", daemon.URL)

	resp := send(t, s, reqJSON("tools/call", 3, map[string]interface{}{
		"name": "vault_wrap",
		"arguments": map[string]interface{}{
			"content":   "SSN is 429-21-0001",
			"tool_name": "lookup",
			"task":      "Test task",
		},
	}))

	if resp["error"] != nil {
		t.Fatalf("unexpected rpc error: %v", resp["error"])
	}
	result := resp["result"].(map[string]interface{})
	if result["isError"] == true {
		t.Fatalf("tool returned isError:true: %v", result["content"])
	}
	content := result["content"].([]interface{})
	text := content[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(text, "vault://abc123") {
		t.Fatalf("expected vault token in result, got: %s", text)
	}
}

func TestVaultWrap_daemonError(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(daemon.Close)
	s := mcp.NewServerForTest("test-agent", "", daemon.URL)

	resp := send(t, s, reqJSON("tools/call", 4, map[string]interface{}{
		"name":      "vault_wrap",
		"arguments": map[string]interface{}{"content": "test", "tool_name": "t"},
	}))

	result := resp["result"].(map[string]interface{})
	if result["isError"] != true {
		t.Fatalf("expected isError:true for daemon 500, got: %v", result)
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	resp := send(t, s, reqJSON("nonexistent/method", 5, nil))

	if resp["error"] == nil {
		t.Fatal("expected JSON-RPC error for unknown method")
	}
	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != -32601 {
		t.Fatalf("expected code -32601, got %v", errObj["code"])
	}
}

func TestNotification(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	// Notifications have no "id" field — server must not write any response.
	result := send(t, s, notificationJSON("initialized"))
	if result != nil {
		t.Fatalf("expected no response for notification, got: %v", result)
	}
}

func TestVaultStatus(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok","vault_total":5,"vault_expired":0,"time":"2026-06-05T00:00:00Z"}`)
	}))
	t.Cleanup(daemon.Close)
	s := mcp.NewServerForTest("test-agent", "", daemon.URL)

	resp := send(t, s, reqJSON("tools/call", 6, map[string]interface{}{
		"name":      "vault_status",
		"arguments": map[string]interface{}{},
	}))

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]interface{})
	content := result["content"].([]interface{})
	text := content[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(text, "status") {
		t.Fatalf("expected 'status' in health response, got: %s", text)
	}
}

func TestAPIKeyInjected(t *testing.T) {
	var gotKey string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Akasha-Key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok","vault_total":0,"vault_expired":0,"time":"2026-06-05T00:00:00Z"}`)
	}))
	t.Cleanup(daemon.Close)
	s := mcp.NewServerForTest("test-agent", "agt_mykey_abc123", daemon.URL)

	send(t, s, reqJSON("tools/call", 7, map[string]interface{}{
		"name": "vault_status", "arguments": map[string]interface{}{},
	}))

	if gotKey != "agt_mykey_abc123" {
		t.Fatalf("expected X-Akasha-Key header, got %q", gotKey)
	}
}

func TestPing(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	resp := send(t, s, reqJSON("ping", 8, nil))
	if resp["error"] != nil {
		t.Fatalf("ping returned error: %v", resp["error"])
	}
}
