package template

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExecuteHelperAWS(t *testing.T) {
	out, err := ExecuteHelper(Get("aws"), map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sk",
		"session_token":     "tok",
	}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["Version"] != float64(1) {
		t.Fatalf("Version = %v", got["Version"])
	}
	if got["AccessKeyId"] != "AKIA" || got["SecretAccessKey"] != "sk" || got["SessionToken"] != "tok" {
		t.Fatalf("fields wrong: %v", got)
	}
	exp, err := time.Parse(time.RFC3339, got["Expiration"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if until := time.Until(exp); until > 16*time.Minute || until < 14*time.Minute {
		t.Fatalf("expiration out of range: %v", exp)
	}
}

func TestExecuteHelperOmitsUnsetOptional(t *testing.T) {
	out, err := ExecuteHelper(Get("aws"), map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sk",
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	json.Unmarshal(out, &got)
	if _, ok := got["SessionToken"]; ok {
		t.Fatal("unset optional field must be omitted")
	}
	if _, ok := got["Expiration"]; ok {
		t.Fatal("ttl=0 must omit Expiration")
	}
}

func TestExecuteHelperMissingRequired(t *testing.T) {
	if _, err := ExecuteHelper(Get("aws"), map[string]string{"access_key_id": "x"}, 0); err == nil {
		t.Fatal("expected error for missing secret_access_key")
	}
}

func TestExecuteHelperNoHelperMode(t *testing.T) {
	tpl, err := Parse([]byte(minimalProvider)) // env-only stripe template
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExecuteHelper(tpl, map[string]string{"api_key": "k"}, 0); err == nil {
		t.Fatal("expected error for template without helper mode")
	}
}

// The builtin github template emits git's credential protocol: sorted
// key=value lines with a unix expiry.
func TestExecuteHelperKVLines(t *testing.T) {
	out, err := ExecuteHelper(Get("github"), map[string]string{"token": "ghp_abc"}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), out)
	}
	// Sorted: password, password_expiry_utc, username.
	if lines[0] != "password=ghp_abc" {
		t.Fatalf("password line = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "password_expiry_utc=") {
		t.Fatalf("expiry line = %q", lines[1])
	}
	epoch, err := strconv.ParseInt(strings.TrimPrefix(lines[1], "password_expiry_utc="), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Until(time.Unix(epoch, 0))
	if until > 16*time.Minute || until < 14*time.Minute {
		t.Fatalf("expiry out of range: %v", until)
	}
	if lines[2] != "username=x-access-token" {
		t.Fatalf("username line = %q", lines[2])
	}
}

// A poisoned secret containing line-control characters must not be able to
// inject extra protocol lines (e.g. forging username= in git's protocol).
func TestExecuteHelperKVLinesRejectsLineInjection(t *testing.T) {
	for _, evil := range []string{"tok\nusername=attacker", "tok\rurl=https://evil", "tok\x00x"} {
		if _, err := ExecuteHelper(Get("github"), map[string]string{"token": evil}, 0); err == nil {
			t.Fatalf("value %q must be refused, not emitted", evil)
		}
	}
}

// JSON output is structurally immune to the same poisoning: the value comes
// back escaped inside its string, never as new JSON structure.
func TestExecuteHelperJSONEscapesPoisonedValue(t *testing.T) {
	poison := "sk\"},\n{\"Injected\":\"x"
	out, err := ExecuteHelper(Get("aws"), map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": poison,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not a single valid JSON object: %v\n%s", err, out)
	}
	if _, ok := got["Injected"]; ok {
		t.Fatal("poisoned value broke out of its JSON string")
	}
	if got["SecretAccessKey"] != poison {
		t.Fatalf("value not preserved verbatim: %q", got["SecretAccessKey"])
	}
}

// Load-time validation: the helper schema rejects unsafe shapes before a
// template can ever execute.
func TestHelperValidation(t *testing.T) {
	cases := map[string]string{
		"contract on helper": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, contract: ssh-agent, format: json, map: {K: k}}]`,
		"unknown format": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: xml, map: {K: k}}]`,
		"emits nothing": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: json}]`,
		"multiline field on kv-lines": `
kind: provider
name: x
version: 1
credential: {fields: {key: {secret: true, multiline: true}}}
deliver: [{mode: helper, format: kv-lines, map: {password: key}}]`,
		"kv-lines key with equals sign": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: kv-lines, map: {"a=b": k}}]`,
		"non-scalar static": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: json, map: {K: k}, static: {Nested: {a: 1}}}]`,
		"duplicate output key": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: json, map: {K: k}, static: {K: 1}}]`,
		"bad expiry format": `
kind: provider
name: x
version: 1
credential: {fields: {k: {secret: true}}}
deliver: [{mode: helper, format: json, map: {K: k}, expiry: {key: E, format: jiffies}}]`,
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected load-time rejection", name)
		}
	}
}
