package escrow

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// Protect works by REPLACING a name: the stub is renamed over the path. That
// does nothing to a second hardlink, which still resolves to the untouched
// plaintext inode — so `✓ escrowed — stub left on disk` was printed for a file
// whose secret was one `cat` away through the other name, with no warning.
func TestProtectRefusesHardlinkedFile(t *testing.T) {
	v := newMemVault()
	path := writeCreds(t)
	other := filepath.Join(filepath.Dir(path), "credentials.bak")
	if err := os.Link(path, other); err != nil {
		t.Skipf("hardlinks unavailable here: %v", err)
	}

	_, err := Protect(v, path)
	if err == nil {
		t.Fatal("protect of a hardlinked file should refuse")
	}
	if !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("the refusal should say why: %v", err)
	}
	if !strings.Contains(err.Error(), other) {
		t.Fatalf("the refusal should name the link that still holds the plaintext: %v", err)
	}
	// Refused before the store, so there is no orphan entry to clean up.
	if len(v.entries) != 0 || len(v.labels) != 0 {
		t.Fatalf("a refused protect wrote to the vault: %v %v", v.entries, v.labels)
	}
	for _, p := range []string{path, other} {
		if got, _ := os.ReadFile(p); string(got) != creds {
			t.Fatalf("a refused protect modified %s", p)
		}
	}

	// A user who knows about the other link can still proceed by saying so.
	if _, err := ProtectWith(v, path, Options{AllowHardlinked: true}); err != nil {
		t.Fatalf("AllowHardlinked should proceed: %v", err)
	}
	if got, _ := os.ReadFile(path); !IsStub(got) {
		t.Fatal("expected a stub after an acknowledged hardlinked protect")
	}
	// And this is exactly what the refusal is about: the secret is still there.
	if got, _ := os.ReadFile(other); string(got) != creds {
		t.Fatal("the other link should still hold the plaintext — that is the finding")
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

// RestoredOnDisk decides whether an escrow label may be removed or re-pointed,
// so every "no" here is a file that survives a removal it would not have
// survived before, and the "yes" is the only case that must open the gate.
func TestRestoredOnDisk(t *testing.T) {
	v := newMemVault()
	path := writeCreds(t)
	if _, err := Protect(v, path); err != nil {
		t.Fatal(err)
	}
	blob, err := v.ValueForLabel(LabelPrefix + path)
	if err != nil {
		t.Fatal(err)
	}

	if RestoredOnDisk(blob, path) {
		t.Fatal("the stub protect leaves is not the original")
	}
	// One byte of anything used to read as "restored", because the test was
	// "not a stub" rather than "the same file".
	os.WriteFile(path, []byte(" "), 0600)
	if RestoredOnDisk(blob, path) {
		t.Fatal("a non-stub file that is not the original must not count")
	}
	// Same length, different bytes: the size check alone is not the answer.
	os.WriteFile(path, bytes.Repeat([]byte("x"), len(creds)), 0600)
	if RestoredOnDisk(blob, path) {
		t.Fatal("same-length foreign content must not count")
	}
	// Opening a fifo from the daemon would block until a writer showed up, so
	// it is rejected on the Lstat, not read.
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err == nil {
		done := make(chan bool, 1)
		go func() { done <- RestoredOnDisk(blob, fifo) }()
		select {
		case got := <-done:
			if got {
				t.Fatal("a fifo is not a copy of anything")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("RestoredOnDisk blocked on a fifo")
		}
	}
	// A missing file, and an envelope whose path is not the one being asked
	// about — the state Restore itself refuses on.
	if RestoredOnDisk(blob, filepath.Join(t.TempDir(), "gone")) {
		t.Fatal("a path the envelope was not written for must not count")
	}
	if RestoredOnDisk("not an envelope", path) {
		t.Fatal("an unparseable entry must not count")
	}

	if err := Restore(v, path); err != nil {
		t.Fatal(err)
	}
	if !RestoredOnDisk(blob, path) {
		t.Fatal("the restored original must count, or protect and label rm both break")
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
