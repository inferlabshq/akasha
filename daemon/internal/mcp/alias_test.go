package mcp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The old tool names keep working for a config written against them, and are
// NOT listed. Listing both spellings would double the model's choice set for
// one operation -- the ambiguity that produced invented tools in the first
// place -- and an alias only exists for callers that already know the name.
func TestOldToolNamesDispatchButAreNotListed(t *testing.T) {
	var paths []string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		http.NotFound(w, r) // the path is the assertion; the body is irrelevant
	}))
	defer daemon.Close()
	s := newTestServer(t, daemon.Config.Handler)

	resp := send(t, s, reqJSON("tools/list", 1, nil))
	tools := resp["result"].(map[string]interface{})["tools"].([]interface{})
	for _, tl := range tools {
		name := tl.(map[string]interface{})["name"].(string)
		if name == "vault_assume" || name == "vault_identity" {
			t.Errorf("old name %q is still listed -- aliases must dispatch, not advertise", name)
		}
	}

	for _, tc := range []struct {
		old, path string
		args      map[string]interface{}
	}{
		{"vault_assume", "/assume", map[string]interface{}{"provider": "aws", "profile": "default"}},
		{"vault_identity", "/identity", map[string]interface{}{"provider": "aws", "profile": "default"}},
	} {
		paths = nil
		resp := send(t, s, reqJSON("tools/call", 2, map[string]interface{}{"name": tc.old, "arguments": tc.args}))
		result, _ := resp["result"].(map[string]interface{})
		if text := resultText(result); strings.Contains(text, "unknown tool") {
			t.Errorf("%s no longer dispatches: %s", tc.old, text)
			continue
		}
		if len(paths) == 0 || paths[0] != tc.path {
			t.Errorf("%s reached the daemon at %v, want %s", tc.old, paths, tc.path)
		}
	}
}

func resultText(result map[string]interface{}) string {
	if result == nil {
		return ""
	}
	content, _ := result["content"].([]interface{})
	var b strings.Builder
	for _, c := range content {
		if m, ok := c.(map[string]interface{}); ok {
			if s, ok := m["text"].(string); ok {
				b.WriteString(s)
			}
		}
	}
	return b.String()
}
