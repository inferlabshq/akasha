package sign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("kind: provider\nname: openclaw\n")
	sig := Sign(content, "openclaw", priv)

	if !sig.Verify(content, pub) {
		t.Fatal("signature should verify with the matching key and content")
	}
	if sig.Publisher != "openclaw" {
		t.Fatalf("publisher = %q", sig.Publisher)
	}
}

func TestVerifyFailsOnTamper(t *testing.T) {
	pub, priv, _ := GenerateKey()
	content := []byte("original")
	sig := Sign(content, "p", priv)
	if sig.Verify([]byte("tampered"), pub) {
		t.Fatal("a changed file must not verify")
	}
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	_, priv, _ := GenerateKey()
	otherPub, _, _ := GenerateKey()
	content := []byte("data")
	sig := Sign(content, "p", priv)
	if sig.Verify(content, otherPub) {
		t.Fatal("a signature must not verify under a different publisher's key")
	}
}

func TestSignatureFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, "x.yaml")
	content := []byte("name: x\n")
	os.WriteFile(tpl, content, 0600)

	pub, priv, _ := GenerateKey()
	if err := WriteSignature(tpl, Sign(content, "pub1", priv)); err != nil {
		t.Fatal(err)
	}

	loaded, ok, err := LoadSignature(tpl)
	if err != nil || !ok {
		t.Fatalf("LoadSignature: ok=%v err=%v", ok, err)
	}
	if !loaded.Verify(content, pub) {
		t.Fatal("loaded signature should verify")
	}

	// No sig file → (nil, false, nil), not an error.
	if _, ok, err := LoadSignature(filepath.Join(dir, "unsigned.yaml")); ok || err != nil {
		t.Fatalf("missing sig should be (false,nil): ok=%v err=%v", ok, err)
	}
}

func TestKeyEncodeDecode(t *testing.T) {
	pub, priv, _ := GenerateKey()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "p.key")
	os.WriteFile(keyPath, []byte(EncodeKey(priv)+"\n"), 0600) // trailing newline tolerated

	loadedPriv, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPub, err := DecodePublicKey(EncodeKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("c")
	if !Sign(content, "p", loadedPriv).Verify(content, loadedPub) {
		t.Fatal("round-tripped keys should sign+verify")
	}

	if _, err := DecodePublicKey("not-base64!!"); err == nil {
		t.Fatal("invalid base64 pubkey should error")
	}
	if _, err := DecodePublicKey(EncodeKey([]byte("too short"))); err == nil {
		t.Fatal("wrong-length pubkey should error")
	}
}
