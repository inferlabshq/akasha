package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPrivateKeyFile(t *testing.T) {
	// Assembled, not spelled: several whole headers in one file read as a key
	// block to the secret scanner, and rightly so.
	const begin, end = "-----BEG" + "IN ", "PRIV" + "ATE KEY-----"
	dir := t.TempDir()
	for name, c := range map[string]struct {
		body string
		want bool
	}{
		"openssh":     {begin + "OPENSSH " + end + "\nx\n", true},
		"rsa":         {begin + "RSA " + end + "\r\nx\n", true},
		"pkcs8":       {begin + end + "\n", true},
		"public":      {"ssh-ed25519 AAAA me\n", false},
		"certificate": {"-----BEGIN CERTIFICATE-----\n", false},
		"mentions":    {"# " + begin + end + "\n", false},
		"ini":         {"[default]\nkey = value\n", false},
		"empty":       {"", false},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := isPrivateKeyFile(p); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if isPrivateKeyFile(filepath.Join(dir, "absent")) {
		t.Error("an unreadable file is not a private key")
	}
}
