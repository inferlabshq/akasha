package assume_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

// An assume that returns only Env is a dead end for a caller whose shell does
// not survive between commands — which is every agent shell measured. It sets
// the variables, they evaporate, and its next command resolves the credential
// from whatever plaintext is still on disk while the audit log records a
// brokered use. The result therefore has to carry a form that works in ONE
// call, and this is the test that it does.
func TestResultCarriesASingleCallRunForm(t *testing.T) {
	res, err := assume.Write("aws", "default", map[string]string{
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secretvalue123",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(res.Path)

	if res.RunVia != "akasha exec --assume aws:default -- <your command>" {
		t.Errorf("run_via = %q, want the akasha exec form for aws:default", res.RunVia)
	}
	// The prefix has to be usable verbatim in front of a command, which means
	// every variable the env carries, quoted.
	for k, v := range res.Env {
		if !strings.Contains(res.RunPrefix, k+"='"+v+"'") {
			t.Errorf("run_prefix %q is missing %s=%s", res.RunPrefix, k, v)
		}
	}
	if res.RunPrefix == "" {
		t.Error("a file-delivered provider must return a run_prefix — its env is a path, not a secret")
	}
}

// The mirror image: a provider whose env delivery materializes the secret
// itself must NOT get a run_prefix. Building one would copy the raw value into
// a second field of the response, and there is nobody who needs it — that path
// is refused to agents upstream, and the human it is returned to has a shell
// that keeps variables.
func TestRunPrefixIsWithheldWhenTheEnvIsTheSecret(t *testing.T) {
	res, err := assume.Write("github", "work", map[string]string{
		"token": "ghp_supersecretvalue",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != "" {
		defer os.Remove(res.Path)
	}
	if res.RunPrefix != "" {
		t.Errorf("run_prefix must be empty for a secret-env provider, got %q", res.RunPrefix)
	}
	if res.RunVia == "" {
		t.Error("run_via is safe for every provider and must still be set")
	}
	if strings.Contains(res.RunPrefix, "ghp_supersecretvalue") {
		t.Error("the raw token reached run_prefix")
	}
}

// Supported answers "does this provider exist", which is what lets the daemon
// tell an unknown provider (404) apart from one it refuses to hand over (403).
func TestSupportedDistinguishesUnknownProviders(t *testing.T) {
	if !assume.Supported("aws") {
		t.Error("aws must be supported")
	}
	if !assume.Supported("env") {
		t.Error("env is the universal fallback and must be supported")
	}
	if assume.Supported("s3") {
		t.Error("s3 is not a provider — reporting it as one is what produced the misleading 403")
	}
}
