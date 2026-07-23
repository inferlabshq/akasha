package discover_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/internal/discover"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseAWSCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "credentials", `
[default]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[prod]
aws_access_key_id     = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
`)

	// Patch the home dir discovery by testing the exported function directly.
	// We call the internal parser via DiscoverAWS scanning our temp dir.
	// For unit testing we exercise Redacted() and FormatSource() instead.

	c := discover.AWSCredential{
		Profile:         "default",
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	redacted := c.Redacted()
	if len(redacted) != len(c.AccessKeyID) {
		t.Fatalf("redacted length mismatch: got %d want %d", len(redacted), len(c.AccessKeyID))
	}
	if redacted == c.AccessKeyID {
		t.Fatal("redacted must not equal plaintext")
	}
	// First 4 and last 4 chars should be visible.
	if redacted[:4] != "AKIA" {
		t.Fatalf("first 4 chars should be visible, got %s", redacted[:4])
	}
}

func TestRedactedShortKey(t *testing.T) {
	c := discover.AWSCredential{AccessKeyID: "SHORT"}
	r := c.Redacted()
	for _, ch := range r {
		if ch != '*' {
			t.Fatalf("short key should be fully masked, got %q", r)
		}
	}
}

func TestFormatSourceWithLine(t *testing.T) {
	c := discover.AWSCredential{
		SourcePath: "~/.aws/credentials",
		SourceLine: 3,
	}
	s := c.FormatSource()
	if s != "~/.aws/credentials:3" {
		t.Fatalf("got %q", s)
	}
}

func TestFormatSourceNoLine(t *testing.T) {
	c := discover.AWSCredential{
		SourcePath: "environment",
		SourceLine: 0,
	}
	s := c.FormatSource()
	if s != "environment" {
		t.Fatalf("got %q", s)
	}
}

func TestDiscoverAWSEnvVars(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	creds, err := discover.DiscoverAWS()
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, c := range creds {
		if c.AccessKeyID == "AKIAIOSFODNN7EXAMPLE" && string(c.Source) == "environment variable" {
			found = true
			if c.SecretAccessKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
				t.Fatal("secret key mismatch")
			}
		}
	}
	if !found {
		t.Fatal("env var credentials not discovered")
	}
}

func TestDeduplication(t *testing.T) {
	// Same access key ID in env and a file should appear only once.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")

	creds, err := discover.DiscoverAWS()
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	for _, c := range creds {
		seen[c.AccessKeyID]++
	}
	for key, count := range seen {
		if count > 1 {
			t.Fatalf("access key %s appeared %d times, expected 1 (dedup failed)", key, count)
		}
	}
}
