package trust

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/internal/publisher"
	"github.com/inferlabshq/akasha/internal/sign"
	"github.com/inferlabshq/akasha/internal/template"
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
