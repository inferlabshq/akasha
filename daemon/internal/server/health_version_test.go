package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/buildinfo"
)

// /health names the build answering, to any caller. An upgraded CLI has no
// other way to tell that the daemon is still the previous build -- the two are
// one binary, but a running daemon keeps the one it started with. Liveness
// tier on purpose: a build string is per-binary and discloses nothing about a
// vault, unlike the counts that stay behind identity.
func TestHealthNamesTheBuildToAnUnidentifiedCaller(t *testing.T) {
	ts, _ := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/health", nil)
	resp, err := (&http.Client{}).Do(req) // bare: no CLI key
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["version"] != buildinfo.Version() {
		t.Errorf("version = %v, want %q", body["version"], buildinfo.Version())
	}
	if _, leaked := body["vault_total"]; leaked {
		t.Error("an unidentified caller was given vault counts -- the version must not have widened the liveness tier")
	}
}
