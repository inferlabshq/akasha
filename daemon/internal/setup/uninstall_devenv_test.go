package setup

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// These tests pin the "uninstall never breaks a developer's environment"
// guarantee end-to-end: original plaintext credentials (which discover only
// ever copies) must survive byte-for-byte, and client configs must be
// restored to their pre-setup shape with user-owned entries untouched.

// realHome is captured at process start, before any test fakes $HOME — the
// OS-keychain subprocess needs it (see escrowAWSCreds).
var realHome = os.Getenv("HOME")

const fakeAWSCreds = `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`

const fakeAWSConfig = `[default]
region = us-east-1
`

const fakeSSHKey = `-----BEGIN OPENSSH PRIVATE KEY-----
NOTAREALKEYNOTAREALKEYNOTAREALKEY
-----END OPENSSH PRIVATE KEY-----
`

// seedDevEnv builds a realistic developer HOME: plaintext credentials, an
// akasha-configured Claude Code + Cursor, and a populated ~/.akasha data dir.
// Returns the data-dir paths for UninstallOptions.
func seedDevEnv(t *testing.T, home string) UninstallOptions {
	t.Helper()

	write := func(rel, content string, perm os.FileMode) string {
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), perm); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// Plaintext credentials a developer relies on.
	write(".aws/credentials", fakeAWSCreds, 0600)
	write(".aws/config", fakeAWSConfig, 0600)
	write(".ssh/id_ed25519", fakeSSHKey, 0600)

	// Claude Code: akasha MCP entry alongside a user-owned server, plus the
	// session env injection setup performs, plus the user's own settings.
	write(".claude.json", `{"mcpServers":{"other":{"command":"/bin/other"}}}`, 0600)
	if err := writeJSONMCP(filepath.Join(home, ".claude.json"), "mcpServers",
		map[string]interface{}{"command": "akasha", "args": []string{"mcp", "--agent-id", "claude"}}); err != nil {
		t.Fatal(err)
	}
	settings := map[string]interface{}{
		"theme": "dark",
		"env": map[string]interface{}{
			"AKASHA_AGENT_ID":  "claude",
			"AKASHA_AGENT_KEY": "agt_secret",
			"AWS_CONFIG_FILE":  filepath.Join(agentsBase(), "claude", "aws.config"),
			"EDITOR":           "vim",
		},
	}
	out, _ := json.MarshalIndent(settings, "", "  ")
	write(".claude/settings.json", string(out), 0600)

	// Cursor: same shape, second client exercised by the deconfigure loop.
	write(".cursor/mcp.json", `{"mcpServers":{"user-db":{"command":"/bin/db"}}}`, 0600)
	if err := writeJSONMCP(filepath.Join(home, ".cursor/mcp.json"), "mcpServers",
		map[string]interface{}{"command": "akasha", "args": []string{"mcp", "--agent-id", "cursor"}}); err != nil {
		t.Fatal(err)
	}

	// Akasha's own data dir. A dummy vault.db is enough: Uninstall tolerates
	// an unopenable vault, and no keychain entry is ever created.
	dataDir := filepath.Join(home, ".akasha")
	write(".akasha/vault.db", "not-a-real-vault", 0600)
	write(".akasha/audit.log", `{"action":"VAULTED"}`+"\n", 0600)

	return UninstallOptions{
		DataDir:    dataDir,
		DBPath:     filepath.Join(dataDir, "vault.db"),
		LogPath:    filepath.Join(dataDir, "audit.log"),
		SocketPath: filepath.Join(dataDir, "akasha.sock"),
	}
}

// mustEqualFile fails if the file's content changed from want.
func mustEqualFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("%s was modified:\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

// Default uninstall: daemon deregistered, akasha config entries removed, and
// EVERYTHING a developer relies on — plaintext credentials, their own MCP
// servers, their own settings — left exactly as it was. Vault data intact.
func TestUninstallDefaultPreservesDevEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)

	if err := Uninstall(opts); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	// Plaintext credentials byte-identical.
	mustEqualFile(t, filepath.Join(home, ".aws/credentials"), fakeAWSCreds)
	mustEqualFile(t, filepath.Join(home, ".aws/config"), fakeAWSConfig)
	mustEqualFile(t, filepath.Join(home, ".ssh/id_ed25519"), fakeSSHKey)

	// Claude Code config: akasha gone, user's server intact.
	var claude map[string]interface{}
	data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	json.Unmarshal(data, &claude)
	servers := claude["mcpServers"].(map[string]interface{})
	if _, ok := servers["akasha"]; ok {
		t.Fatal("akasha MCP entry survived uninstall in .claude.json")
	}
	if _, ok := servers["other"]; !ok {
		t.Fatal("user's own MCP server was removed from .claude.json")
	}

	// Cursor config: same guarantee.
	var cursor map[string]interface{}
	data, _ = os.ReadFile(filepath.Join(home, ".cursor/mcp.json"))
	json.Unmarshal(data, &cursor)
	servers = cursor["mcpServers"].(map[string]interface{})
	if _, ok := servers["akasha"]; ok {
		t.Fatal("akasha MCP entry survived uninstall in cursor mcp.json")
	}
	if _, ok := servers["user-db"]; !ok {
		t.Fatal("user's own MCP server was removed from cursor mcp.json")
	}

	// Session env: akasha-owned vars gone, user's vars and settings intact.
	var settings map[string]interface{}
	data, _ = os.ReadFile(filepath.Join(home, ".claude/settings.json"))
	json.Unmarshal(data, &settings)
	if settings["theme"] != "dark" {
		t.Fatal("user's theme setting was dropped")
	}
	env, _ := settings["env"].(map[string]interface{})
	for _, gone := range []string{"AKASHA_AGENT_ID", "AKASHA_AGENT_KEY", "AWS_CONFIG_FILE"} {
		if _, ok := env[gone]; ok {
			t.Fatalf("injected env var %s survived uninstall", gone)
		}
	}
	if env["EDITOR"] != "vim" {
		t.Fatal("user's own EDITOR env var was removed")
	}

	// Non-purge leaves the vault untouched.
	if _, err := os.Stat(opts.DBPath); err != nil {
		t.Fatal("default uninstall must leave vault.db in place")
	}
	if _, err := os.Stat(opts.LogPath); err != nil {
		t.Fatal("default uninstall must leave audit.log in place")
	}
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns what it
// printed. Uninstall reports everything through stdout, so its claims about
// what was and wasn't cleaned are only assertable from there.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	os.Stdout = prev
	w.Close()
	out := <-done
	r.Close()
	return out
}

// GUARANTEE: `uninstall --purge` never prints "fully removed" while leaving env
// vars behind that point into the directory it just deleted. VS Code-family
// settings.json is canonically JSONC, so the settings file cannot be rewritten
// — the user MUST be told to finish by hand, before the data dir goes.
func TestUninstallPurgeWarnsWhenSettingsCannotBeCleaned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	opts.Purge = true
	opts.Yes = true

	// Replace Claude Code's settings with the JSONC shape akasha refuses to
	// rewrite, keeping the injected vars in it.
	settings := filepath.Join(home, ".claude/settings.json")
	jsonc := "// my settings\n{\n  \"env\": {\"AKASHA_AGENT_ID\": \"claude\"}\n}\n"
	if err := os.WriteFile(settings, []byte(jsonc), 0600); err != nil {
		t.Fatal(err)
	}

	var err error
	out := captureStdout(t, func() { err = Uninstall(opts) })
	if err != nil {
		t.Fatalf("Uninstall --purge: %v", err)
	}

	// The file akasha would not parse is untouched, injected vars and all.
	mustEqualFile(t, settings, jsonc)

	// The warning must name the file and appear BEFORE the data dir is removed,
	// so a user watching the output can still act on it.
	if !strings.Contains(out, "~/.claude/settings.json") {
		t.Fatalf("uninstall never mentioned the settings file it could not clean:\n%s", out)
	}
	warnIdx, removeIdx := strings.Index(out, "~/.claude/settings.json"), strings.Index(out, "removed ~/.akasha")
	if removeIdx >= 0 && warnIdx > removeIdx {
		t.Fatalf("warning must precede the destructive removal:\n%s", out)
	}
	if strings.Contains(out, "Akasha fully removed") {
		t.Fatalf("uninstall claimed success with akasha env vars still wired up:\n%s", out)
	}
}

// escrowAWSCreds swaps the seeded dummy vault.db for a real vault and escrows
// ~/.aws/credentials into it, leaving a stub on disk — the only copy of the
// original bytes is now the vault. The keychain write inside vault.Open blocks
// under a faked $HOME, so the vault is opened with the real HOME restored
// (test binaries use an isolated per-PID keychain service either way) and the
// open handle is injected into Uninstall via the openVaultForUninstall seam.
func escrowAWSCreds(t *testing.T, home string, opts UninstallOptions) {
	t.Helper()
	os.Remove(opts.DBPath)

	fakeHome := os.Getenv("HOME")
	os.Setenv("HOME", realHome)
	vlt, err := vault.Open(opts.DBPath, vault.Options{AllowNewVaultKey: true})
	os.Setenv("HOME", fakeHome)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}

	credsPath := filepath.Join(home, ".aws/credentials")
	if _, err := escrow.Protect(escrow.Direct{Vault: vlt}, credsPath); err != nil {
		t.Fatalf("Protect: %v", err)
	}
	stub, _ := os.ReadFile(credsPath)
	if !escrow.IsStub(stub) {
		t.Fatal("credentials file should be a stub after protect")
	}

	// Hand the already-open handle to Uninstall (all later vault operations
	// are DB-only and never touch the keychain, so the faked HOME is fine).
	prev := openVaultForUninstall
	openVaultForUninstall = func(string) (*vault.Vault, error) { return vlt, nil }
	t.Cleanup(func() { openVaultForUninstall = prev })
}

// After protect, the plaintext's only copy is the vault — a default uninstall
// must put the original back byte-for-byte, or Akasha has broken the machine.
func TestUninstallRestoresEscrowedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	escrowAWSCreds(t, home, opts)

	if err := Uninstall(opts); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	mustEqualFile(t, filepath.Join(home, ".aws/credentials"), fakeAWSCreds)
}

// Purge is about to destroy the vault, so escrowed originals must be restored
// to disk first — otherwise purge would destroy the only copy of a file the
// user still needs.
func TestUninstallPurgeRestoresEscrowedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	escrowAWSCreds(t, home, opts)
	opts.Purge = true
	opts.Yes = true

	if err := Uninstall(opts); err != nil {
		t.Fatalf("Uninstall --purge: %v", err)
	}
	if _, err := os.Stat(opts.DataDir); !os.IsNotExist(err) {
		t.Fatal("purge should remove the data dir")
	}
	mustEqualFile(t, filepath.Join(home, ".aws/credentials"), fakeAWSCreds)
}

// Purge: the akasha data dir is destroyed, but original plaintext credentials
// still survive — Akasha never held the only copy of a discovered secret.
func TestUninstallPurgePreservesOriginalCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts := seedDevEnv(t, home)
	opts.Purge = true
	opts.Yes = true

	if err := Uninstall(opts); err != nil {
		t.Fatalf("Uninstall --purge: %v", err)
	}

	if _, err := os.Stat(opts.DataDir); !os.IsNotExist(err) {
		t.Fatalf("purge should remove %s entirely (err=%v)", opts.DataDir, err)
	}

	mustEqualFile(t, filepath.Join(home, ".aws/credentials"), fakeAWSCreds)
	mustEqualFile(t, filepath.Join(home, ".aws/config"), fakeAWSConfig)
	mustEqualFile(t, filepath.Join(home, ".ssh/id_ed25519"), fakeSSHKey)
}
