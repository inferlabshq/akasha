package trust

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/publisher"
	"github.com/inferlabshq/akasha/daemon/internal/sign"
	"github.com/inferlabshq/akasha/daemon/internal/template"
)

const ownProvider = `
kind: provider
name: acme
version: 1
credential: {fields: {token: {secret: true}}}
deliver: [{mode: env, env: {ACME: "{token}"}}]
agent:
  own:
    - mechanism: decoy
      env: ACME_CONFIG
      file: acme.conf
`

// inertProvider has no system-modifying effect: it delivers only on-demand via
// the credential_process helper (no file written, no env set, no agent/source/
// discover block), so it carries no sensitive capability and needs no approval.
const inertProvider = `
kind: provider
name: plain
version: 1
credential: {fields: {token: {secret: true}}}
deliver: [{mode: helper, format: kv-lines, static: {username: token}, map: {password: token}}]
`

// loadTemplate writes a template into a temp dir, points the search path at it,
// and returns the loaded *Template (with Origin set) plus its file path.
func loadTemplate(t *testing.T, name, body string) (*template.Template, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)
	tpl := template.Get(name)
	if tpl == nil {
		t.Fatalf("template %q failed to load", name)
	}
	return tpl, path
}

func storeAt(t *testing.T) *Store {
	t.Helper()
	t.Setenv("AKASHA_APPROVALS_FILE", filepath.Join(t.TempDir(), "approvals.json"))
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApproveAndPersist(t *testing.T) {
	tpl, _ := loadTemplate(t, "acme", ownProvider)
	s := storeAt(t)

	if ok, _ := s.Approved(tpl); ok {
		t.Fatal("a sensitive template must not be approved by default")
	}
	if err := s.Approve(tpl); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Approved(tpl); !ok {
		t.Fatal("template should be approved after Approve")
	}

	// Persisted: a fresh load sees the approval.
	reloaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := reloaded.Approved(tpl); !ok {
		t.Fatal("approval did not persist")
	}
}

// TestEditRevokesApproval is the TOCTOU property: editing the file after
// approval changes its hash, so it is no longer approved until re-approved.
func TestEditRevokesApproval(t *testing.T) {
	tpl, path := loadTemplate(t, "acme", ownProvider)
	s := storeAt(t)
	if err := s.Approve(tpl); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Approved(tpl); !ok {
		t.Fatal("should be approved")
	}

	// Tamper with the file (append a harmless comment) and reload it.
	if err := os.WriteFile(path, []byte(ownProvider+"\n# tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	template.ResetForTest()
	edited := template.Get("acme")
	if ok, _ := s.Approved(edited); ok {
		t.Fatal("a file edited after approval must NOT be approved (hash mismatch)")
	}
}

func TestInertTemplateAlwaysApproved(t *testing.T) {
	tpl, _ := loadTemplate(t, "plain", inertProvider)
	s := storeAt(t)
	// No sensitive capabilities → approved without any record.
	if ok, err := s.Approved(tpl); err != nil || !ok {
		t.Fatalf("inert template should be approved: ok=%v err=%v", ok, err)
	}
}

func TestRevoke(t *testing.T) {
	tpl, _ := loadTemplate(t, "acme", ownProvider)
	s := storeAt(t)
	s.Approve(tpl)
	if !s.Revoke("acme") {
		t.Fatal("Revoke should report a removal")
	}
	if ok, _ := s.Approved(tpl); ok {
		t.Fatal("revoked template must not be approved")
	}
	if s.Revoke("acme") {
		t.Fatal("second Revoke should report nothing removed")
	}
}

// TestSignatureConfersApproval is the hands-off path: a sensitive template
// validly signed by a trusted publisher is approved WITHOUT any manual record.
func TestSignatureConfersApproval(t *testing.T) {
	// Fresh publisher store.
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	// Write a sensitive (agent-block) template into a dir, sign it, and load it.
	pk, priv, _ := sign.GenerateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	if err := os.WriteFile(path, []byte(ownProvider), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteSignature(path, sign.Sign([]byte(ownProvider), "acme-pub", priv)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)
	tpl := template.Get("acme")
	if tpl == nil {
		t.Fatal("template failed to load")
	}

	s := storeAt(t) // empty manual approval store

	// Not trusted yet → not approved (no signature trust, no manual record).
	if ok, _ := s.Approved(tpl); ok {
		t.Fatal("must not be approved before trusting the publisher")
	}
	// Trust the publisher → approved with no manual approval.
	if err := publisher.Add("acme-pub", "Acme", sign.EncodeKey(pk)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Approved(tpl); err != nil || !ok {
		t.Fatalf("signed-by-trusted-publisher should be approved: ok=%v err=%v", ok, err)
	}
}

func TestCorruptStoreErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	os.WriteFile(path, []byte("{ not json"), 0600)
	if _, err := LoadFrom(path); err == nil {
		t.Fatal("a corrupt approvals file should error, not be silently ignored")
	}
}

// The release property: a SIGNED provider stays approved across an upgrade that
// edits its file, so users are not re-prompted every release.
//
// Signature trust is checked before the hash-bound record, so re-signing an
// edited template carries approval forward. Unsigned, the same edit revokes it
// (TestEditRevokesApproval) — which is correct for a file that changed under
// you, and is exactly why the shipped bundle must be signed.
func TestResignedTemplateStaysApprovedAcrossReleases(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	pk, priv, _ := sign.GenerateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	if err := os.WriteFile(path, []byte(ownProvider), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteSignature(path, sign.Sign([]byte(ownProvider), "acme-pub", priv)); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Add("acme-pub", "Acme", sign.EncodeKey(pk)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	s := storeAt(t) // deliberately empty: no manual approval anywhere
	if ok, _ := s.Approved(template.Get("acme")); !ok {
		t.Fatal("signed template should be approved before the upgrade")
	}

	// Release N+1: the template's bytes change and the publisher re-signs.
	next := ownProvider + "\n# a comment added in the next release\n"
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteSignature(path, sign.Sign([]byte(next), "acme-pub", priv)); err != nil {
		t.Fatal(err)
	}
	template.ResetForTest()

	if ok, err := s.Approved(template.Get("acme")); err != nil || !ok {
		t.Fatalf("a re-signed template must stay approved across releases: ok=%v err=%v", ok, err)
	}
}

// Editing a signed template WITHOUT re-signing must lose trust — otherwise the
// signature would be decoration rather than a check on the bytes.
func TestTamperedSignedTemplateLosesApproval(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	pk, priv, _ := sign.GenerateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	os.WriteFile(path, []byte(ownProvider), 0600)
	if err := sign.WriteSignature(path, sign.Sign([]byte(ownProvider), "acme-pub", priv)); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Add("acme-pub", "Acme", sign.EncodeKey(pk)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)

	s := storeAt(t)
	if ok, _ := s.Approved(template.Get("acme")); !ok {
		t.Fatal("signed template should start approved")
	}

	// Tamper without re-signing.
	os.WriteFile(path, []byte(ownProvider+"\n# unsigned edit\n"), 0600)
	template.ResetForTest()

	if ok, _ := s.Approved(template.Get("acme")); ok {
		t.Fatal("a template edited after signing must not stay approved")
	}
}

// TestSwapAfterLoadIsNotApproved is the property the hash binding exists for
// once you allow a same-UID attacker to write the file: approval is judged
// against the bytes the daemon LOADED, so placing a malicious template, letting
// it load, and restoring the approved file leaves the loaded structure
// unapproved — the approved file's hash never vouches for other bytes.
func TestSwapAfterLoadIsNotApproved(t *testing.T) {
	tpl, path := loadTemplate(t, "acme", ownProvider)
	s := storeAt(t)
	if err := s.Approve(tpl); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Approved(tpl); !ok {
		t.Fatal("should be approved")
	}

	// The attacker's template is what actually loads...
	if err := os.WriteFile(path, []byte(ownProvider+"\n# the attacker's version\n"), 0600); err != nil {
		t.Fatal(err)
	}
	template.ResetForTest()
	loaded := template.Get("acme")
	// ...and the approved file is back before anything checks it.
	if err := os.WriteFile(path, []byte(ownProvider), 0600); err != nil {
		t.Fatal(err)
	}

	if ok, _ := s.Approved(loaded); ok {
		t.Fatal("a template loaded from swapped bytes must NOT be approved on the strength of the restored file")
	}
}

// The same swap against the signature path: a template must not inherit the
// signature of a file restored beneath it after it loaded.
func TestSwapAfterLoadDoesNotBorrowASignature(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	pk, priv, _ := sign.GenerateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	if err := os.WriteFile(path, []byte(ownProvider), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteSignature(path, sign.Sign([]byte(ownProvider), "acme-pub", priv)); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Add("acme-pub", "Acme", sign.EncodeKey(pk)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)

	if err := os.WriteFile(path, []byte(ownProvider+"\n# the attacker's version\n"), 0600); err != nil {
		t.Fatal(err)
	}
	template.ResetForTest()
	t.Cleanup(template.ResetForTest)
	loaded := template.Get("acme")
	if err := os.WriteFile(path, []byte(ownProvider), 0600); err != nil {
		t.Fatal(err)
	}

	s := storeAt(t)
	if ok, _ := s.Approved(loaded); ok {
		t.Fatal("a swapped-in template must NOT be approved by the signature on the file restored under it")
	}
}
