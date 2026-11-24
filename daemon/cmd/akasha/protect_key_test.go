package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPrivateKeyFile(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		body string
		want bool
	}{
		"openssh":     {"-----BEGIN OPENSSH PRIVATE KEY-----\nx\n", true},
		"rsa":         {"-----BEGIN RSA PRIVATE KEY-----\r\nx\n", true},
		"pkcs8":       {"-----BEGIN PRIVATE KEY-----\n", true},
		"public":      {"ssh-ed25519 AAAA me\n", false},
		"certificate": {"-----BEGIN CERTIFICATE-----\n", false},
		"mentions":    {"# -----BEGIN PRIVATE KEY-----\n", false},
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
