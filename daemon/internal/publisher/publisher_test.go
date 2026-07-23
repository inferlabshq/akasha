package publisher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/internal/sign"
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

func TestOfficialKeyUnprovisioned(t *testing.T) {
	// The committed official.pub is a placeholder (comments only) → no official
	// key, so Trusted() has no official entry by default.
	t.Setenv("AKASHA_PUBLISHERS_FILE", filepath.Join(t.TempDir(), "pub.json"))
	trusted, err := Trusted()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := trusted[OfficialID]; ok {
		t.Fatal("official key should be absent until provisioned")
	}
}
