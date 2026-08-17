package assume

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// symlinkOrSkip skips the test on a platform (or filesystem) that will not make
// a symlink; the squat these tests describe cannot happen there either.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
}

// A base that is really a symlink is the /dev/shm squat: another local account
// creates akasha-<uid> pointing at a directory it controls before the daemon's
// first run. It must not be used, and the user must still get a session dir.
func TestSessionDirRefusesSymlinkedBase(t *testing.T) {
	tmp := t.TempDir()
	planted := filepath.Join(tmp, "attacker")
	if err := os.Mkdir(planted, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "base")
	symlinkOrSkip(t, planted, link)

	SetSessionBase(link)
	defer SetSessionBase("")

	dir, err := sessionDir()
	if err != nil {
		t.Fatalf("a hostile base must fall back to a safe location, not fail: %v", err)
	}
	if strings.HasPrefix(dir, planted+string(os.PathSeparator)) || strings.HasPrefix(dir, link+string(os.PathSeparator)) {
		t.Fatalf("session dir followed the planted symlink: %s", dir)
	}
	if _, err := os.Stat(filepath.Join(planted, "sessions")); !os.IsNotExist(err) {
		t.Fatalf("a sessions dir was created through the symlink, stat err=%v", err)
	}
	if err := verifyPrivateDir(link); err == nil {
		t.Fatal("verifyPrivateDir accepted a symlink")
	}
}

// The same squat with a plain file (or anything else that is not a directory)
// in place of the expected directory.
func TestVerifyPrivateDirRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "base")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(path); err == nil {
		t.Fatal("verifyPrivateDir accepted a regular file")
	}
}

// A pre-created directory carries the mode its creator chose — MkdirAll's 0700
// applies only when it does the creating. Credential files must never end up
// inside a directory other users can reach.
func TestSessionDirNeverUsesAGroupOrOtherAccessibleDir(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	if err := os.Mkdir(base, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0777); err != nil { // defeat umask
		t.Fatal(err)
	}
	SetSessionBase(base)
	defer SetSessionBase("")

	dir, err := sessionDir()
	if err != nil {
		t.Fatalf("sessionDir: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("session dir is mode %04o, reachable by other users", perm)
	}
	if strings.HasPrefix(dir, base+string(os.PathSeparator)) {
		if fi, err := os.Lstat(base); err != nil {
			t.Fatal(err)
		} else if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("session base left at mode %04o, reachable by other users", perm)
		}
	}
}

// A directory owned by somebody else can only be arranged as root, which is how
// CI containers usually run; elsewhere the case cannot be staged.
func TestVerifyPrivateDirRejectsForeignOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a directory owned by another uid")
	}
	dir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skipf("cannot chown to nobody here: %v", err)
	}
	if err := verifyPrivateDir(dir); err == nil {
		t.Fatal("verifyPrivateDir accepted a directory owned by another uid")
	}
}

// A symlink planted at the leaf redirects the private key itself. The write must
// fail, and the link's target must be left untouched.
func TestWriteSessionFileRefusesSymlinkAtLeaf(t *testing.T) {
	base := t.TempDir()
	SetSessionBase(base)
	defer SetSessionBase("")

	dir, err := sessionDir()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "attacker-target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, target, filepath.Join(dir, "id_key"))

	if _, err := writeSessionFile(dir, "id_key", []byte("PRIVATE KEY"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("writeSessionFile followed a symlink at the leaf")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("the symlink target was overwritten: %q", data)
	}
}

// The ordinary path: 0600, exact bytes, and the expiry encoded as mtime — the
// sweeper reads no index, only that timestamp.
func TestWriteSessionFileHappyPath(t *testing.T) {
	base := t.TempDir()
	SetSessionBase(base)
	defer SetSessionBase("")

	dir, err := sessionDir()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(37 * time.Minute).UTC()
	path, err := writeSessionFile(dir, "creds", []byte("body"), expires)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %04o", fi.Mode().Perm())
	}
	if d := fi.ModTime().Sub(expires); d > time.Second || d < -time.Second {
		t.Fatalf("mtime %v is not the expiry %v", fi.ModTime(), expires)
	}
	if data, _ := os.ReadFile(path); string(data) != "body" {
		t.Fatalf("content mismatch: %q", data)
	}

	// Re-assuming the same provider/profile overwrites its own leftover file.
	later := time.Now().Add(2 * time.Hour).UTC()
	if _, err := writeSessionFile(dir, "creds", []byte("second"), later); err != nil {
		t.Fatalf("rewriting an existing session file: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "second" {
		t.Fatalf("rewrite did not replace the file: %q", data)
	}
	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if d := fi.ModTime().Sub(later); d > time.Second || d < -time.Second {
		t.Fatalf("rewritten mtime %v is not the new expiry %v", fi.ModTime(), later)
	}
}
