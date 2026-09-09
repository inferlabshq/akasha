package server_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A successful /assume materializes a real credential file with the real secret
// in it, so where that file lands is a property of the harness worth asserting
// directly. It used to land in the developer's actual ~/.akasha/sessions: a
// review agent's reproduction of an assume call left a live plaintext AWS
// credential in a real home directory, invisible because the tests that assume
// only ever os.Remove the path they are handed and never ask where it points.
func TestAssumeWritesTheCredentialFileInsideTheTestSessionBase(t *testing.T) {
	ts, vlt := newTestServer(t)
	trustBundle(t)
	seedAWS(t, vlt, "isolation", testAccount)

	assertInsideTestSessionBase(t, assumeCredFile(t, ts, "isolation"))
}

// The same property through a DIFFERENT constructor, because that is where this
// went wrong the first time: isolating one test server left the other five
// standing servers writing wherever assume.Write chose, and a package that was
// demonstrably clean through newTestServer still dropped aws-default.creds and
// ssh-gitlab.key into the real data directory on every run.
func TestAssumeFromAnotherTestServerStaysInsideTheSessionBase(t *testing.T) {
	e := newRunTestServer(t, "rules: []\n")
	trustBundle(t)
	seedAWS(t, e.vlt, "run-isolation", testAccount)

	assertInsideTestSessionBase(t, assumeCredFile(t, e.ts, "run-isolation"))
}

// assumeCredFile assumes aws:<profile> and returns the path of the file that
// came back.
func assumeCredFile(t *testing.T, ts *httptest.Server, profile string) string {
	t.Helper()
	code, out := post(t, ts, "/assume", map[string]string{
		"provider": "aws", "profile": profile,
	}, "")
	if code != 200 {
		t.Fatalf("assume failed: %d %v", code, out)
	}
	env, _ := out["env"].(map[string]interface{})
	path, _ := env["AWS_SHARED_CREDENTIALS_FILE"].(string)
	if path == "" {
		t.Fatalf("no credentials file path: %v", out)
	}
	return path
}

// assertInsideTestSessionBase fails unless path is inside the temp base TestMain
// owns and deletes.
//
// Reading the file back is the part that matters. A returned path under the temp
// base proves nothing on its own if the bytes went somewhere else, so this
// asserts on the file that actually holds the decrypted secret.
func assertInsideTestSessionBase(t *testing.T, path string) {
	t.Helper()
	if testSessionBase == "" {
		t.Fatal("TestMain should have pinned a session base")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back the file the assume wrote: %v", err)
	}
	if !strings.Contains(string(data), secretKeyValue) {
		t.Fatalf("%s is not the credential file this assume produced", path)
	}
	if !strings.HasPrefix(path, testSessionBase+string(os.PathSeparator)) {
		t.Fatalf("a live plaintext credential was written to %s, outside the test session base %s", path, testSessionBase)
	}
	// Named separately from the containment check above because this is the
	// specific escape that happened, and it is the one a reader needs to see
	// fail. Compared as strings — probing the real data directory to find out
	// would itself be a test reaching into the developer's home.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if strings.HasPrefix(path, filepath.Join(home, ".akasha")+string(os.PathSeparator)) {
			t.Fatalf("a live plaintext credential was written into the real data directory: %s", path)
		}
	}
}
