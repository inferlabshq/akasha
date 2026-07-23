package assume_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

func TestWriteAWS(t *testing.T) {
	creds := map[string]string{
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secretvalue123",
	}
	res, err := assume.Write("aws", "default", creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(res.Path)

	// Env must point at the file and set the profile.
	if res.Env["AWS_SHARED_CREDENTIALS_FILE"] != res.Path {
		t.Fatalf("env file mismatch: %v", res.Env)
	}
	if res.Env["AWS_PROFILE"] != "default" {
		t.Fatalf("expected AWS_PROFILE=default, got %v", res.Env["AWS_PROFILE"])
	}

	// File must contain the credentials in AWS ini format, mode 0600.
	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(res.Path)
	body := string(data)
	if !strings.Contains(body, "[default]") ||
		!strings.Contains(body, "AKIAEXAMPLE") ||
		!strings.Contains(body, "secretvalue123") {
		t.Fatalf("file missing expected content:\n%s", body)
	}
}

func TestWriteAWSWithSessionToken(t *testing.T) {
	creds := map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sk",
		"session_token":     "tok123",
	}
	res, err := assume.Write("aws", "prod", creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(res.Path)
	data, _ := os.ReadFile(res.Path)
	if !strings.Contains(string(data), "aws_session_token = tok123") {
		t.Fatal("session token not written")
	}
}

func TestWriteAWSMissingFields(t *testing.T) {
	_, err := assume.Write("aws", "default", map[string]string{"access_key_id": "only"}, time.Hour)
	if err == nil {
		t.Fatal("expected error for missing secret_access_key")
	}
}

func TestWriteGitHubEnvOnly(t *testing.T) {
	res, err := assume.Write("github", "inferlabs", map[string]string{"token": "ghp_abc"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Env["GITHUB_TOKEN"] != "ghp_abc" {
		t.Fatalf("expected GITHUB_TOKEN, got %v", res.Env)
	}
	if res.Path != "" {
		t.Fatal("token-only providers should not write a file")
	}
}

func TestWriteSSH(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----"
	res, err := assume.Write("ssh", "gitlab", map[string]string{"private_key": key}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(res.Path)

	// GIT_SSH_COMMAND must reference the key file with IdentitiesOnly.
	cmd := res.Env["GIT_SSH_COMMAND"]
	if !strings.Contains(cmd, res.Path) || !strings.Contains(cmd, "IdentitiesOnly=yes") {
		t.Fatalf("GIT_SSH_COMMAND wrong: %s", cmd)
	}
	if res.Env["SSH_KEY_PATH"] != res.Path {
		t.Fatalf("SSH_KEY_PATH mismatch")
	}

	// File must be 0600 and end with a newline.
	info, _ := os.Stat(res.Path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(res.Path)
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatal("key file must end with newline")
	}
}

func TestWriteSSHMissingKey(t *testing.T) {
	_, err := assume.Write("ssh", "x", map[string]string{}, time.Hour)
	if err == nil {
		t.Fatal("expected error for missing private_key")
	}
}

func TestWriteGitLabToken(t *testing.T) {
	res, err := assume.Write("gitlab", "inferlabs", map[string]string{"token": "glpat-xyz"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Env["GITLAB_TOKEN"] != "glpat-xyz" {
		t.Fatalf("expected GITLAB_TOKEN, got %v", res.Env)
	}
}

func TestSupportedProviders(t *testing.T) {
	got := assume.SupportedProviders()
	want := map[string]bool{"aws": true, "gcp": true, "github": true, "gitlab": true, "git": true, "ssh": true, "env": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d providers, got %d: %v", len(want), len(got), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("unexpected provider %q", p)
		}
	}
}

func TestUnsupportedProvider(t *testing.T) {
	_, err := assume.Write("dropbox", "x", map[string]string{}, time.Hour)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

// Path-traversal / injection guard: malicious profile names must be rejected
// before any file is written.
func TestWriteRejectsPathTraversal(t *testing.T) {
	creds := map[string]string{"access_key_id": "AKIA", "secret_access_key": "sk"}
	bad := []string{
		"../../../tmp/evil",
		"..",
		".",
		"a/b",
		`a\b`,
		"name with space",
		"newline\ninjected",
		"profile[evil]",
		"",
	}
	for _, p := range bad {
		if _, err := assume.Write("aws", p, creds, time.Hour); err == nil {
			t.Fatalf("expected rejection for profile %q", p)
		}
	}
}

func TestWriteAcceptsSafeNames(t *testing.T) {
	creds := map[string]string{"access_key_id": "AKIA", "secret_access_key": "sk"}
	for _, p := range []string{"default", "pk-website", "id_ed25519", "granular-lucene_key.pem", "my.project"} {
		res, err := assume.Write("aws", p, creds, time.Hour)
		if err != nil {
			t.Fatalf("safe profile %q rejected: %v", p, err)
		}
		os.Remove(res.Path)
	}
}

func TestWriteEnvGeneric(t *testing.T) {
	// Field names become env var names; no file written.
	res, err := assume.Write("env", "stripe", map[string]string{
		"STRIPE_API_KEY": "sk_live_xyz",
		"STRIPE_WEBHOOK": "whsec_abc",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Env["STRIPE_API_KEY"] != "sk_live_xyz" || res.Env["STRIPE_WEBHOOK"] != "whsec_abc" {
		t.Fatalf("env mapping wrong: %v", res.Env)
	}
	if res.Path != "" {
		t.Fatal("env provider should not write a file")
	}
}

func TestWriteEnvEmpty(t *testing.T) {
	if _, err := assume.Write("env", "x", map[string]string{}, time.Hour); err == nil {
		t.Fatal("expected error for empty env fields")
	}
}

func TestExpirySet(t *testing.T) {
	res, err := assume.Write("github", "x", map[string]string{"token": "t"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(res.ExpiresAt) > 31*time.Second || time.Until(res.ExpiresAt) < 25*time.Second {
		t.Fatalf("expiry out of range: %v", res.ExpiresAt)
	}
}
