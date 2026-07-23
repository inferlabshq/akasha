package escrow

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// memVault is an in-memory escrow.Vault for unit tests.
type memVault struct {
	entries map[string]string // token -> plaintext
	labels  map[string]string // label -> token
	n       int
	failSet bool
}

func newMemVault() *memVault {
	return &memVault{entries: map[string]string{}, labels: map[string]string{}}
}

func (m *memVault) Store(plaintext, category, risk, agentID, tool string, ttl time.Duration) (string, error) {
	m.n++
	tok := "vault://" + strings.Repeat("t", 4) + string(rune('a'+m.n))
	m.entries[tok] = plaintext
	return tok, nil
}

func (m *memVault) ValueForLabel(name string) (string, error) {
	tok, ok := m.labels[name]
	if !ok {
		return "", os.ErrNotExist
	}
	return m.entries[tok], nil
}

func (m *memVault) SetLabel(name, token string) error {
	if m.failSet {
		return os.ErrPermission
	}
	m.labels[name] = token
	return nil
}

func (m *memVault) ListLabels(prefix string) ([]string, error) {
	var out []string
	for l := range m.labels {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out, nil
}

const creds = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = sekrit\n"

func writeCreds(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte(creds), 0640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProtectRestoreRoundtrip(t *testing.T) {
	v := newMemVault()
	path := writeCreds(t)

	if _, err := Protect(v, path); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	// On-disk file is now a stub: comment-only, no secret material, 0600.
	got, _ := os.ReadFile(path)
	if !IsStub(got) {
		t.Fatal("file should be a stub after protect")
	}
	if strings.Contains(string(got), "sekrit") {
		t.Fatal("stub leaked secret content")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(got)), "\n") {
		if !strings.HasPrefix(line, "#") {
			t.Fatalf("stub line not a comment: %q", line)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Fatalf("stub mode = %v, want 0600", fi.Mode().Perm())
	}
	if !IsEscrowed(v, path) {
		t.Fatal("IsEscrowed should be true after protect")
	}

	// Restore: byte-identical content AND original mode (0640, not 0600).
	if err := Restore(v, path); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, _ = os.ReadFile(path)
	if !bytes.Equal(got, []byte(creds)) {
		t.Fatalf("restore not verbatim:\n%s", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0640 {
		t.Fatalf("restored mode = %v, want original 0640", fi.Mode().Perm())
	}
}

// Protecting a stub must be refused — it would destroy the vaulted original.
func TestProtectRefusesStub(t *testing.T) {
	v := newMemVault()
	path := writeCreds(t)
	if _, err := Protect(v, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Protect(v, path); err == nil || !strings.Contains(err.Error(), "already an escrow stub") {
		t.Fatalf("double-protect should refuse: %v", err)
	}
}

func TestProtectRefusesSymlinkAndMissing(t *testing.T) {
	v := newMemVault()
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.WriteFile(real, []byte("x"), 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Protect(v, link); err == nil {
		t.Fatal("protect of a symlink should refuse")
	}
	if _, err := Protect(v, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("protect of a missing file should error")
	}
}

// A failure AFTER the vault write but BEFORE the stub write leaves the
// original untouched — durability-first ordering.
func TestProtectFailureLeavesOriginal(t *testing.T) {
	v := newMemVault()
	v.failSet = true
	path := writeCreds(t)
	if _, err := Protect(v, path); err == nil {
		t.Fatal("expected SetLabel failure to propagate")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte(creds)) {
		t.Fatal("original must be untouched when protect fails")
	}
}

func TestRestoreWithoutEscrow(t *testing.T) {
	v := newMemVault()
	if err := Restore(v, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("restore without an escrow entry should error")
	}
}

func TestListAndReprotectAfterRestore(t *testing.T) {
	v := newMemVault()
	path := writeCreds(t)
	if _, err := Protect(v, path); err != nil {
		t.Fatal(err)
	}
	paths, err := List(v)
	if err != nil || len(paths) != 1 || paths[0] != path {
		t.Fatalf("List: %v %v", paths, err)
	}

	// Restore, edit, protect again — the label now points at the new bytes.
	if err := Restore(v, path); err != nil {
		t.Fatal(err)
	}
	edited := creds + "aws_session_token = zzz\n"
	os.WriteFile(path, []byte(edited), 0640)
	if _, err := Protect(v, path); err != nil {
		t.Fatalf("re-protect of a restored (real) file should work: %v", err)
	}
	if err := Restore(v, path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != edited {
		t.Fatal("re-protect should have captured the edited content")
	}
}

// Envelope must survive arbitrary bytes (not just text).
func TestBinaryContentVerbatim(t *testing.T) {
	v := newMemVault()
	path := filepath.Join(t.TempDir(), "blob")
	raw := []byte{0x00, 0xff, 0x1b, '\n', 0x80, 0x7f}
	os.WriteFile(path, raw, 0600)
	if _, err := Protect(v, path); err != nil {
		t.Fatal(err)
	}
	if err := Restore(v, path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, raw) {
		t.Fatalf("binary content mangled: %v", got)
	}
}
