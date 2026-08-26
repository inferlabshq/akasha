package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// `akasha protect` moves a credential FILE into the vault, so an escrow entry's
// value is the plaintext the user took off disk — there is no brokered form of
// "the bytes of a file". Under the shipped default policy that value came back
// to any key-holding agent in ONE request:
//
//	GET /credential/retrieve?name=escrow:/root/.aws/credentials   → 200, the file
//
// because that endpoint is gated as `assume` and `assume` ships permissive so
// routine git/aws work is not interrupted. The same agent's POST /retrieve was
// correctly refused, which is what made this an authorization gap rather than a
// design choice: protect's central claim ("agents can no longer read it") was
// false for the exact caller it was written about.
//
// Every test below asserts the same pair of properties, because either alone is
// a bug: the AGENT is refused, and the OWNER is not. A `deny`/`ask` policy rule
// gets the first half and fails the second — on a headless machine it locks the
// user out of their own file, which turns a protected credential into a lost
// one.

const escrowFixtureSecret = "aws_secret_access_key = FIXTURE-NOT-A-REAL-KEY"

// protectFixture escrows a credentials file into vlt exactly as the CLI does,
// leaving the stub on disk. Returns the path, its escrow label and the token.
func protectFixture(t *testing.T, vlt *vault.Vault) (path, label, token string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("[default]\n"+escrowFixtureSecret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := escrow.Protect(escrow.Direct{Vault: vlt}, path)
	if err != nil {
		t.Fatalf("protect fixture: %v", err)
	}
	label, err = escrow.Label(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, label, token
}

// humanGet issues a GET as the local CLI (ts.Client() carries its key).
func humanGet(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// keyedPost is post() for responses that are not JSON — a 403 or a 409 carries
// the daemon's prose, and the remediation text is the thing worth asserting on.
func keyedPost(t *testing.T, ts *httptest.Server, path string, body interface{}, key string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Akasha-Key", key)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

// escrowedContent decodes a /credential/retrieve response into the file bytes
// the envelope carries, so a test asserts on the plaintext itself rather than
// on whether some encoding of it happens to appear in the body.
func escrowedContent(t *testing.T, body string) []byte {
	t.Helper()
	var res struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil || res.Value == "" {
		t.Fatalf("no value in response: %s", body)
	}
	var env escrow.Envelope
	if err := json.Unmarshal([]byte(res.Value), &env); err != nil {
		t.Fatalf("value is not an escrow envelope: %v", err)
	}
	return env.Content
}

// leaksSecret reports whether a response body carries the fixture secret in any
// of the shapes it could arrive in — verbatim, or base64 inside an envelope.
func leaksSecret(body string) bool {
	if strings.Contains(body, escrowFixtureSecret) {
		return true
	}
	var res struct {
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(body), &res) != nil || res.Value == "" {
		return false
	}
	var env escrow.Envelope
	if json.Unmarshal([]byte(res.Value), &env) != nil {
		return strings.Contains(res.Value, escrowFixtureSecret)
	}
	return bytes.Contains(env.Content, []byte(escrowFixtureSecret))
}

func TestAgentCannotReadAnEscrowedFile(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, label, token := protectFixture(t, vlt)
	_, agentKey, err := vlt.CreateAgentKey("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	nameQuery := "/credential/retrieve?name=" + url.QueryEscape(label)

	// The owner still gets their file back, byte for byte. Without this half the
	// test would pass for a fix that simply broke restore.
	code, body := humanGet(t, ts, nameQuery)
	if code != 200 {
		t.Fatalf("the owner must still read their own escrowed file: %d %s", code, body)
	}
	if !bytes.Contains(escrowedContent(t, body), []byte(escrowFixtureSecret)) {
		t.Fatal("the owner's restore path did not return the original bytes")
	}

	// The agent, holding a real verified key, gets nothing.
	code, body = keyedGet(t, ts, nameQuery, agentKey)
	if code != http.StatusForbidden {
		t.Fatalf("agent read of an escrowed file: got %d, want 403\nbody: %s", code, body)
	}
	if leaksSecret(body) {
		t.Fatal("the refusal body carried the escrowed plaintext")
	}

	// And not by token either. /retrieve was already denied by the shipped
	// policy's `action: retrieve` rule — but that rule is a FILE the user can
	// edit or delete, and with no policy installed the engine allows
	// everything, which is the state a fresh install is in.
	code, body = keyedPost(t, ts, "/retrieve",
		map[string]string{"token": token, "requesting_tool": "read_file"}, agentKey)
	if code != http.StatusForbidden {
		t.Fatalf("agent /retrieve of an escrow token: got %d, want 403\nbody: %s", code, body)
	}
	if leaksSecret(body) {
		t.Fatal("the refusal body carried the escrowed plaintext")
	}
}

// The guard keys on the entry's CATEGORY, not on the name it was asked for.
// Checking the "escrow:" prefix alone would be walked the same way the policy
// gate was walked before authorizeCredentialNames: bind a second name to the
// token, then ask under that one.
func TestEscrowGateIsNotBypassedByAnAlias(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, _, token := protectFixture(t, vlt)
	_, agentKey, err := vlt.CreateAgentKey("claude-code")
	if err != nil {
		t.Fatal(err)
	}

	// The alias is minted by the human, so the write gate is not what is under
	// test here — the read gate is.
	if code, body := keyedPost(t, ts, "/label/set",
		map[string]string{"name": "zz:1", "token": token}, ""); code != 200 {
		t.Fatalf("precondition: the human should be able to bind an alias: %d %s", code, body)
	}

	code, body := keyedGet(t, ts, "/credential/retrieve?name=zz:1", agentKey)
	if code != http.StatusForbidden {
		t.Fatalf("aliased escrow read: got %d, want 403\nbody: %s", code, body)
	}
	if leaksSecret(body) {
		t.Fatal("the alias returned the escrowed plaintext")
	}
}

// The label list is the reconnaissance step: `GET /label/list?prefix=escrow:`
// hands an agent the absolute path of every credential file the user protected.
// They are also not assumable, so vault_status was advertising them under
// "assumable" — a list of things an agent is told it can use and cannot.
func TestAgentCannotEnumerateEscrowLabels(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, label, _ := protectFixture(t, vlt)
	_, agentKey, err := vlt.CreateAgentKey("claude-code")
	if err != nil {
		t.Fatal(err)
	}

	code, body := humanGet(t, ts, "/label/list?prefix=")
	if code != 200 || !strings.Contains(body, label) {
		t.Fatalf("the owner must see their escrow labels: %d %s", code, body)
	}

	for _, path := range []string{"/label/list?prefix=", "/label/list?prefix=escrow%3A"} {
		code, body := keyedGet(t, ts, path, agentKey)
		if code != 200 {
			t.Fatalf("%s: an agent listing labels should still work, got %d %s", path, code, body)
		}
		if strings.Contains(body, label) || strings.Contains(body, escrow.LabelPrefix) {
			t.Fatalf("%s: escrow labels leaked to an agent: %s", path, body)
		}
	}
}

// The write half. Removing the escrow label orphans the original; re-pointing it
// at a token of the agent's choosing does the same thing with an extra step, and
// makes the next `akasha restore` write the agent's bytes over the user's file.
func TestAgentCannotUnbindOrRebindAnEscrowLabel(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, label, _ := protectFixture(t, vlt)
	_, agentKey, err := vlt.CreateAgentKey("claude-code")
	if err != nil {
		t.Fatal(err)
	}

	decoy, err := vlt.Store("not the user's file", "Credential", "low", "claude-code", "vault_store", 0)
	if err != nil {
		t.Fatal(err)
	}

	if code, body := keyedPost(t, ts, "/label/delete", map[string]interface{}{"name": label}, agentKey); code != http.StatusForbidden {
		t.Fatalf("agent unbind of an escrow label: got %d, want 403\nbody: %s", code, body)
	}
	if code, body := keyedPost(t, ts, "/label/set",
		map[string]string{"name": label, "token": decoy}, agentKey); code != http.StatusForbidden {
		t.Fatalf("agent rebind of an escrow label: got %d, want 403\nbody: %s", code, body)
	}
	// Preview is a probe, not a read, but it is still the escrow inventory.
	if code, body := keyedPost(t, ts, "/label/delete",
		map[string]interface{}{"name": label, "preview": true}, agentKey); code != http.StatusForbidden {
		t.Fatalf("agent preview of an escrow label: got %d, want 403\nbody: %s", code, body)
	}

	// The label still points where it did, so the user's file is still there.
	if got, err := vlt.GetLabel(label); err != nil || got == decoy {
		t.Fatalf("escrow label was moved: %q %v", got, err)
	}
}

// `akasha label rm --yes escrow:<path>` printed "✓ removed" and left the user
// with a stub on disk and no way to reach the original — while its own warning
// said to recover by re-running `akasha discover` "if the source still exists".
// The source IS the stub. This is the one label removal that destroys data, and
// it has to be refused by the daemon rather than by the CLI that prints that
// warning, because the endpoint is reachable without it.
func TestUnbindEscrowRefusesWhileTheStubIsOnDisk(t *testing.T) {
	ts, vlt := newTestServer(t)
	path, label, token := protectFixture(t, vlt)

	code, body := keyedPost(t, ts, "/label/delete", map[string]interface{}{"name": label}, "")
	if code != http.StatusConflict {
		t.Fatalf("removing an escrow label over its own stub: got %d, want 409\nbody: %s", code, body)
	}
	if !strings.Contains(body, "akasha restore") {
		t.Fatalf("the refusal must name the reversal, got: %s", body)
	}
	if got, err := vlt.GetLabel(label); err != nil || got != token {
		t.Fatalf("label was removed anyway: %q %v", got, err)
	}

	// Restore the file, and the same removal becomes what it claims to be — a
	// name cleanup — because the bytes now exist somewhere else.
	if err := escrow.Restore(escrow.Direct{Vault: vlt}, path); err != nil {
		t.Fatal(err)
	}
	if code, body := keyedPost(t, ts, "/label/delete", map[string]interface{}{"name": label}, ""); code != 200 {
		t.Fatalf("after restore, removing the label should be allowed: %d %s", code, body)
	}
}

// The escape hatch, for the case that would otherwise strand a user: the file's
// directory is gone, so `akasha restore` cannot put it back and the label could
// never be removed. It must be a NAMED confirmation, not --yes: the user is
// agreeing to lose a file, not to skip a prompt.
//
// Both halves are asserted in one test on purpose. "Destroy succeeds" alone is
// a claim that holds just as well when the guard above it has been deleted, so
// on its own it pins nothing; what has to stay true is the DIFFERENCE the flag
// makes on an otherwise identical request.
func TestUnbindEscrowHonoursTheNamedConfirmation(t *testing.T) {
	ts, vlt := newTestServer(t)
	_, label, _ := protectFixture(t, vlt)

	if code, body := keyedPost(t, ts, "/label/delete",
		map[string]interface{}{"name": label}, ""); code != http.StatusConflict {
		t.Fatalf("without the named flag this removal must be refused: got %d, want 409\nbody: %s", code, body)
	}

	code, body := keyedPost(t, ts, "/label/delete",
		map[string]interface{}{"name": label, "destroy_escrowed_original": true}, "")
	if code != 200 {
		t.Fatalf("explicit destroy should be allowed: %d %s", code, body)
	}
	if _, err := vlt.GetLabel(label); err == nil {
		t.Fatal("label should be gone")
	}
}

// "Is the file on disk a stub?" was a PROXY for "does this file still exist
// anywhere but the vault?", and the thing it inspected is writable by the very
// caller the escrow gate keeps away from /label/delete. Any non-stub bytes at
// that path — a comment, a blank line, a truncated copy — made the daemon
// answer "restored, safe to remove", and the removal that followed destroyed
// the original. The question is now decided against the escrowed bytes.
func TestUnbindEscrowComparesTheBytesNotTheStubMarker(t *testing.T) {
	ts, vlt := newTestServer(t)
	path, label, token := protectFixture(t, vlt)

	// The original bytes, taken from the vault rather than restated here, so
	// this test cannot pass by comparing a fixture with itself.
	if err := escrow.Restore(escrow.Direct{Vault: vlt}, path); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	decoys := map[string][]byte{
		"the stub protect leaves": escrow.StubContent(path),
		"unrelated content":       []byte("[default]\n# nothing to see here\n"),
		// Same length as the original, so nothing but the content itself
		// separates it from the real file.
		"same length, different bytes": bytes.Repeat([]byte("x"), len(original)),
		"truncated original":           original[:len(original)-1],
	}
	for what, content := range decoys {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		code, body := keyedPost(t, ts, "/label/delete", map[string]interface{}{"name": label}, "")
		if code != http.StatusConflict {
			t.Fatalf("%s at the escrow path: got %d, want 409\nbody: %s", what, code, body)
		}
		if got, err := vlt.GetLabel(label); err != nil || got != token {
			t.Fatalf("%s: the label was removed anyway: %q %v", what, got, err)
		}
		// And the preview says the same thing, because that is what `akasha
		// label rm` prints its "back on disk, this only forgets the entry" line
		// from — a claim the CLI cannot check for itself.
		if _, pv := keyedPost(t, ts, "/label/delete",
			map[string]interface{}{"name": label, "preview": true}, ""); !strings.Contains(pv, `"escrow_only_copy":true`) {
			t.Fatalf("%s: the preview told the CLI the original was safe: %s", what, pv)
		}
	}

	// The real file, byte for byte, is the only thing that clears it.
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if code, body := keyedPost(t, ts, "/label/delete", map[string]interface{}{"name": label}, ""); code != 200 {
		t.Fatalf("with the original back on disk the removal should be allowed: %d %s", code, body)
	}
}

// The rebind is the same destruction as the unbind, and it has a shipped CLI
// route: `akasha put escrow:/home/me/.aws/credentials --stdin` re-pointed the
// label and printed "✓ stored under escrow:…". Afterwards `akasha restore`
// failed with an envelope path mismatch, and `akasha uninstall --purge` — the
// documented escape hatch — failed the same way and purged the vault anyway.
// The file was gone for good.
//
// The guard had been hung on /label/delete rather than on the escrow binding,
// so it fenced one of two doors. This is the human's half; the agent is refused
// outright by TestAgentCannotUnbindOrRebindAnEscrowLabel.
func TestHumanCannotRebindAnEscrowLabelOverItsOriginal(t *testing.T) {
	ts, vlt := newTestServer(t)
	path, label, token := protectFixture(t, vlt)

	// The shipped route: `akasha put escrow:<path> --stdin`.
	code, body := keyedPost(t, ts, "/put", map[string]interface{}{
		"label": label, "fields": map[string]string{"foo": "bar"},
	}, "")
	if code != http.StatusConflict {
		t.Fatalf("`akasha put %s`: got %d, want 409\nbody: %s", label, code, body)
	}
	if !strings.Contains(body, "akasha restore") {
		t.Fatalf("the refusal must name the reversal, got: %s", body)
	}

	// And the same operation one layer down, which is what /put ends in.
	decoy, err := vlt.Store("not the user's file", "Credential", "low", "", "vault_store", 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := keyedPost(t, ts, "/label/set",
		map[string]string{"name": label, "token": decoy}, ""); code != http.StatusConflict {
		t.Fatalf("re-pointing an escrow label: got %d, want 409\nbody: %s", code, body)
	}

	// Nothing moved, so the file is still there — the property the whole guard
	// exists for.
	if got, err := vlt.GetLabel(label); err != nil || got != token {
		t.Fatalf("the escrow label was re-pointed anyway: %q %v", got, err)
	}
	if err := escrow.Restore(escrow.Direct{Vault: vlt}, path); err != nil {
		t.Fatalf("the escrowed original is no longer restorable: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Contains(got, []byte(escrowFixtureSecret)) {
		t.Fatalf("restore did not put the original back: %v %q", err, got)
	}

	// With the file back on disk the name is free again: the refusal is about
	// the file, not about the namespace.
	if code, body := keyedPost(t, ts, "/put", map[string]interface{}{
		"label": label, "fields": map[string]string{"foo": "bar"},
	}, ""); code != 200 {
		t.Fatalf("after restore, rebinding the name should be allowed: %d %s", code, body)
	}

	// And the name that now holds ordinary fields is an ordinary name: there is
	// no escrowed original behind it any more, so cleaning it up must not
	// demand the flag that exists for destroying a file.
	if code, body := keyedPost(t, ts, "/label/delete", map[string]interface{}{"name": label}, ""); code != 200 {
		t.Fatalf("an escrow-shaped name over a non-escrow entry should be removable: %d %s", code, body)
	}
}

// The one rebind that strands nothing: `akasha protect` escrowing a file it
// already holds, after the user restored and then edited it. The replacement
// entry is a fresher copy of the same file, so refusing it would break protect
// itself — the command the whole feature is named after.
func TestReprotectingAnEscrowedFileIsStillAllowed(t *testing.T) {
	ts, vlt := newTestServer(t)
	path, label, _ := protectFixture(t, vlt)
	if err := escrow.Restore(escrow.Direct{Vault: vlt}, path); err != nil {
		t.Fatal(err)
	}
	edited := []byte("[default]\n" + escrowFixtureSecret + "\nregion = ap-southeast-2\n")
	if err := os.WriteFile(path, edited, 0600); err != nil {
		t.Fatal(err)
	}
	if code, body := keyedPost(t, ts, "/label/set",
		map[string]string{"name": label, "token": envelopeToken(t, vlt, path, edited)}, ""); code != 200 {
		t.Fatalf("re-protecting an escrowed file: %d %s", code, body)
	}

	// The exemption is for THIS file. An envelope for some other path replaces
	// the only handle on this one with something that is not it, which is the
	// original loss with a costume on.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	other := envelopeToken(t, vlt, elsewhere, []byte("someone else's file"))
	if err := os.WriteFile(path, escrow.StubContent(path), 0600); err != nil {
		t.Fatal(err)
	}
	if code, body := keyedPost(t, ts, "/label/set",
		map[string]string{"name": label, "token": other}, ""); code != http.StatusConflict {
		t.Fatalf("an envelope for a different path must not unlock the rebind: got %d, want 409\nbody: %s", code, body)
	}
}

// A miss on a lookup ends in a hint about what WOULD resolve, and the generic
// one ("run `akasha discover <p>` or `akasha put <p>:<name>`") rendered for the
// escrow provider as `akasha put escrow:<name>` — the exact command that
// re-points an escrow label away from the file it is the only handle on. It was
// printed to a user who had just failed to find a file, which is when they are
// most likely to type back what they are told.
func TestTheEscrowMissDoesNotAdviseTheDestructiveCommand(t *testing.T) {
	// Nothing escrowed — the state the generic hint is written for, and the one
	// a user who has just lost track of a protected file is most likely in.
	ts, _ := newTestServer(t)
	miss := "/credential/retrieve?name=" + url.QueryEscape(escrow.LabelPrefix+"/no/such/file")
	code, body := humanGet(t, ts, miss)
	if code != http.StatusNotFound {
		t.Fatalf("got %d, want 404\nbody: %s", code, body)
	}
	if strings.Contains(body, "akasha put "+escrow.LabelPrefix) {
		t.Fatalf("the miss advised the command that destroys an escrowed original: %s", body)
	}
	if !strings.Contains(body, "akasha protect") {
		t.Fatalf("the miss should point at the command that DOES create escrow entries: %s", body)
	}

	// With something escrowed the hint lists instances instead; it must not
	// slip the same advice in on that path either.
	ts2, vlt2 := newTestServer(t)
	protectFixture(t, vlt2)
	if _, body := humanGet(t, ts2, miss); strings.Contains(body, "akasha put "+escrow.LabelPrefix) {
		t.Fatalf("the populated hint advised it instead: %s", body)
	}
}

// envelopeToken vaults an escrow envelope for path exactly as `akasha protect`
// does — Store first, then bind the name — so a test can drive the bind gate
// the way protect drives it rather than reaching past the daemon.
func envelopeToken(t *testing.T, vlt *vault.Vault, path string, content []byte) string {
	t.Helper()
	blob, err := json.Marshal(escrow.Envelope{Version: 1, Path: path, Mode: 0600, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	token, err := vlt.Store(string(blob), escrow.Category, "critical", escrow.AgentID, "akasha_protect", 0)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
