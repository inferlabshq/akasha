package publisher

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/sign"
)

// signedTemplate writes a template file and a valid .sig for it by `pubID`.
func signedTemplate(t *testing.T, pubID string) (path string, pub []byte) {
	t.Helper()
	pk, priv, _ := sign.GenerateKey()
	dir := t.TempDir()
	path = filepath.Join(dir, pubID+".yaml")
	content := []byte("kind: provider\nname: x\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteSignature(path, sign.Sign(content, pubID, priv)); err != nil {
		t.Fatal(err)
	}
	return path, pk
}

func TestVerifyTemplateWithTrustedPublisher(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	path, pub := signedTemplate(t, "openclaw")

	// Signed but publisher not trusted yet → not verified.
	if _, ok, _ := VerifyTemplate(path); ok {
		t.Fatal("must not verify before the publisher is trusted")
	}

	if err := Add("openclaw", "OpenClaw", sign.EncodeKey(pub)); err != nil {
		t.Fatal(err)
	}
	id, ok, err := VerifyTemplate(path)
	if err != nil || !ok || id != "openclaw" {
		t.Fatalf("VerifyTemplate = %q,%v,%v", id, ok, err)
	}

	// Tamper after signing → no longer verifies.
	os.WriteFile(path, []byte("kind: provider\nname: x\n# tampered\n"), 0600)
	if _, ok, _ := VerifyTemplate(path); ok {
		t.Fatal("tampered file must not verify")
	}
}

func TestVerifyUnsignedAndWrongPublisher(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	// Unsigned file → (",false,nil).
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "u.yaml")
	os.WriteFile(unsigned, []byte("name: u\n"), 0600)
	if _, ok, err := VerifyTemplate(unsigned); ok || err != nil {
		t.Fatalf("unsigned should be (false,nil): ok=%v err=%v", ok, err)
	}

	// Signed by a publisher we don't trust → not verified.
	path, _ := signedTemplate(t, "stranger")
	if _, ok, _ := VerifyTemplate(path); ok {
		t.Fatal("signature by an untrusted publisher must not verify")
	}
}

func TestAddValidationAndRemove(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))

	if err := Add("bad", "", "not-base64!!"); err == nil {
		t.Fatal("invalid key should be rejected")
	}
	if err := Add(OfficialID, "", "x"); err == nil {
		t.Fatal("overriding the official publisher must be rejected")
	}

	pub, _, _ := sign.GenerateKey()
	if err := Add("acme", "Acme", sign.EncodeKey(pub)); err != nil {
		t.Fatal(err)
	}
	trusted, _ := Trusted()
	if _, ok := trusted["acme"]; !ok {
		t.Fatal("acme should be trusted after Add")
	}
	removed, err := Remove("acme")
	if err != nil || !removed {
		t.Fatalf("Remove acme = %v,%v", removed, err)
	}
	if removed, _ := Remove("acme"); removed {
		t.Fatal("second Remove should report nothing removed")
	}
}

// The trust root was provisioned on 2026-08-20, so a build from this tree
// carries an official key and Trusted() includes it with no publishers file.
// This is the inverse of the assertion that stood while official.pub was a
// placeholder: the bundle is now hands-off-trusted, and a build that lost the
// key would send every user back to approving each provider by hand.
func TestOfficialKeyIsProvisioned(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	trusted, err := Trusted()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := trusted[OfficialID]; !ok {
		t.Fatal("official key is missing — the shipped bundle would need manual approval")
	}
}

// OfficialConfigured gates the release workflow, which refuses to publish a
// build that cannot verify official signatures. The key is compiled in, so a
// binary that ships without it can never be repaired after the fact — only a
// new release reaches users.
func TestOfficialConfiguredIsTrueOnceProvisioned(t *testing.T) {
	if !OfficialConfigured() {
		t.Error("official.pub is not parsing as a key — the release guard will refuse to publish this build")
	}
	if _, ok := officialKey(); !ok {
		t.Error("officialKey() and OfficialConfigured() disagree")
	}
}

// OfficialConfigured must track officialKey exactly — the release guard and the
// verifier have to agree on what "configured" means, or CI will pass a build
// that cannot verify its own bundle.
func TestOfficialConfiguredMatchesKeyParsing(t *testing.T) {
	saved := officialPubRaw
	t.Cleanup(func() { officialPubRaw = saved })

	pub, _, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	officialPubRaw = "# a comment\n\n" + sign.EncodeKey(pub) + "\n"
	if !OfficialConfigured() {
		t.Error("a real key line should count as configured")
	}

	officialPubRaw = "# comments only\n\n"
	if OfficialConfigured() {
		t.Error("comments-only must not count as configured")
	}

	// A present-but-malformed key must NOT be treated as configured: shipping
	// that would produce a build whose signature checks silently never pass.
	officialPubRaw = "not-a-valid-base64-ed25519-key\n"
	if OfficialConfigured() {
		t.Error("a malformed key must not count as configured")
	}
}

// TestVerifyTemplateDigestBindsToTheCallersBytes is the anti-TOCTOU property:
// a signature vouches for a caller's structure only when the file still holds
// the bytes that structure was parsed from. A caller that cannot name its bytes
// gets a refusal, never a fallback to the unbound check.
func TestVerifyTemplateDigestBindsToTheCallersBytes(t *testing.T) {
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	path, pub := signedTemplate(t, "openclaw")
	if err := Add("openclaw", "OpenClaw", sign.EncodeKey(pub)); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	id, ok, err := VerifyTemplateDigest(path, hex.EncodeToString(sum[:]))
	if err != nil || !ok || id != "openclaw" {
		t.Fatalf("VerifyTemplateDigest = %q,%v,%v for the signed bytes", id, ok, err)
	}

	other := sha256.Sum256([]byte("kind: provider\nname: x\n# the bytes actually loaded\n"))
	if _, ok, _ := VerifyTemplateDigest(path, hex.EncodeToString(other[:])); ok {
		t.Fatal("a signature over the file must not verify bytes the caller loaded elsewhere")
	}
	if _, ok, _ := VerifyTemplateDigest(path, ""); ok {
		t.Fatal("an empty digest must not fall back to verifying whatever is on disk")
	}
}
