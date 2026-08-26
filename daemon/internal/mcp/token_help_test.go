package mcp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/mcp"
)

// callText drives one tools/call against a stub daemon and returns the text the
// model would see, plus whether it was flagged as an error.
func callText(t *testing.T, daemonBody string, status int, tool string, args map[string]interface{}) (string, bool) {
	t.Helper()
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, daemonBody, status)
	}))
	t.Cleanup(daemon.Close)
	s := mcp.NewServerForTest("test-agent", "", daemon.URL)

	resp := send(t, s, reqJSON("tools/call", 1, map[string]interface{}{
		"name": tool, "arguments": args,
	}))
	result := resp["result"].(map[string]interface{})
	content := result["content"].([]interface{})
	return content[0].(map[string]interface{})["text"].(string), result["isError"] == true
}

// "token not found" is the single most-produced error on this surface, and it
// named no next step. A model with no token cannot construct one, so what it
// does with a dead end is invent: across 19 such errors, a third of the next
// actions were calls to tools that do not exist (vault_show, vault_login,
// vault_authenticate) and only one in six found vault_status. Naming the
// recovery took invented tools to zero.
func TestTokenErrorsNameTheCallThatWouldHaveWorked(t *testing.T) {
	for _, tc := range []struct {
		tool     string
		args     map[string]interface{}
		daemon   string
		status   int
		scenario string
	}{
		{"vault_retrieve", map[string]interface{}{"token": "vault://AWSAccessKeyID", "requesting_tool": "aws"},
			"token not found", http.StatusForbidden, "invented token"},
		{"vault_retrieve", map[string]interface{}{"token": "AWSAccessKeyID", "requesting_tool": "aws"},
			"invalid token format", http.StatusForbidden, "not even a vault:// token"},
		{"vault_inspect", map[string]interface{}{"token": "vault://my-s3-token"},
			"token not found", http.StatusNotFound, "invented token on inspect"},
	} {
		text, isErr := callText(t, tc.daemon, tc.status, tc.tool, tc.args)
		if !isErr {
			t.Errorf("%s: expected an error result", tc.scenario)
		}
		for _, want := range []string{"vault_status", "vault_assume", "vault_identity", "cannot be guessed"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: %s error does not mention %q:\n%s", tc.scenario, tc.tool, want, text)
			}
		}
	}
}

// vault_grant takes a token too, so it fails the same way and for the same
// reason — a caller that was never handed one invents it — and it was the one
// member of the class left undecorated: "cannot grant unknown token: token not
// found", with no next step, from a tool the catalog offers every agent.
func TestGrantOfAnInventedTokenGetsTheSameRecovery(t *testing.T) {
	text, isErr := callText(t, "cannot grant unknown token: token not found", http.StatusBadRequest,
		"vault_grant", map[string]interface{}{
			"token": "vault://AWSAccessKeyID", "grantee_agent": "other-agent",
		})
	if !isErr {
		t.Fatal("expected an error result")
	}
	for _, want := range []string{"vault_status", "vault_assume", "cannot be guessed"} {
		if !strings.Contains(text, want) {
			t.Errorf("vault_grant's token error does not mention %q:\n%s", want, text)
		}
	}
}

// The other half of B4: the calls that arrive without the two arguments at all.
// Every one of these used to reach the daemon and come back with "provider and
// profile required", which names neither the format nor a next call. The
// `label` form is in here because the schema has no such property — a caller
// that has seen `aws:default` written somewhere passes it as the only thing it
// has, and gets an empty refusal for an argument it never sent.
func TestAssumeWithoutBothArgumentsNamesTheFormat(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())

	for _, args := range []map[string]interface{}{
		{},
		{"label": "aws:default"},
		{"provider": "aws:default"},
		{"provider": "aws"},
	} {
		resp := send(t, s, reqJSON("tools/call", 1, map[string]interface{}{
			"name": "vault_assume", "arguments": args,
		}))
		result := resp["result"].(map[string]interface{})
		text := result["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
		if result["isError"] != true {
			t.Errorf("vault_assume%v: expected an error result", args)
		}
		for _, want := range []string{"provider=\"aws\"", "profile=\"default\"", "aws:default", "vault_status"} {
			if !strings.Contains(text, want) {
				t.Errorf("vault_assume%v: refusal does not mention %q:\n%s", args, want, text)
			}
		}
	}
}

// vault_inspect's own missing-argument error is produced without touching the
// daemon, and it was the emptiest message of the lot.
func TestInspectWithNoArgumentsRoutesToVaultStatus(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	resp := send(t, s, reqJSON("tools/call", 1, map[string]interface{}{
		"name": "vault_inspect", "arguments": map[string]interface{}{},
	}))
	result := resp["result"].(map[string]interface{})
	text := result["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(text, "vault_status") {
		t.Errorf("a caller with neither a token nor a grant must be sent to vault_status:\n%s", text)
	}
}

// The recovery is earned by token errors and nothing else. A policy denial is a
// DECISION, and appending "call vault_status, then vault_assume" to it would be
// teaching a model to retry a refusal by another route.
func TestPolicyDenialIsNotDecoratedWithTokenRecovery(t *testing.T) {
	text, isErr := callText(t,
		"denied by policy rule \"no-critical-reads\"", http.StatusForbidden,
		"vault_retrieve", map[string]interface{}{"token": "vault://real", "requesting_tool": "aws"})
	if !isErr {
		t.Fatal("expected an error result")
	}
	if strings.Contains(text, "cannot be guessed") {
		t.Errorf("a policy denial must not be answered with token-recovery advice:\n%s", text)
	}
	if !strings.Contains(text, "no-critical-reads") {
		t.Errorf("the daemon's own reason must survive:\n%s", text)
	}
}

// The token-taking tools are the two a model cannot use unaided — 19/19 and 6/6
// of their calls failed in testing, every one on a token the model made up. The
// description has to say so before the call, not only after it.
func TestTokenTakingToolsSayTheyNeedATokenYouWereGiven(t *testing.T) {
	s := newTestServer(t, http.NotFoundHandler())
	resp := send(t, s, reqJSON("tools/list", 1, nil))
	tools := resp["result"].(map[string]interface{})["tools"].([]interface{})

	descs := map[string]string{}
	for _, raw := range tools {
		tl := raw.(map[string]interface{})
		descs[tl["name"].(string)] = tl["description"].(string)
	}
	for _, name := range []string{"vault_retrieve", "vault_inspect"} {
		if !strings.Contains(descs[name], "only have a token if an earlier tool call handed you one") {
			t.Errorf("%s must say up front that a token cannot be invented:\n%s", name, descs[name])
		}
	}
	// vault_assume's result is useless to a caller that just sets the env and
	// stops — 14 of 16 successful assumes ended exactly that way.
	if !strings.Contains(descs["vault_assume"], "run_via") || !strings.Contains(descs["vault_assume"], "akasha exec --assume") {
		t.Errorf("vault_assume must tell a stateless caller how to APPLY the result:\n%s", descs["vault_assume"])
	}
	// A model that has no credential must not be taught to create one.
	if !strings.Contains(descs["vault_store"], "invented") {
		t.Errorf("vault_store must say that storing an invented value is not a fix:\n%s", descs["vault_store"])
	}
}
