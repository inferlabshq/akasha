package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A RAM disk is claimed by name in a shared namespace (/Volumes), so the
// ownership/mode predicate is the only thing standing between a materialized
// credential and a volume someone else mounted first.
func TestSafeSessionDir(t *testing.T) {
	root := t.TempDir()

	good := filepath.Join(root, "good")
	if err := os.Mkdir(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safeSessionDir(good); err != nil {
		t.Fatalf("0700 dir owned by us rejected: %v", err)
	}

	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o702, 0o720} {
		dir := filepath.Join(root, "mode")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := safeSessionDir(dir); err == nil {
			t.Errorf("mode %04o accepted; group- or world-writable session storage is the whole risk", mode)
		}
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
	}

	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safeSessionDir(file); err == nil {
		t.Error("a regular file was accepted as session storage")
	}

	link := filepath.Join(root, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := safeSessionDir(link); err == nil {
		t.Error("a symlink was accepted; the check must not follow it off the mount point")
	}

	if err := safeSessionDir(filepath.Join(root, "absent")); err == nil {
		t.Error("a missing path was accepted")
	}
}

func TestMountEntryDevice(t *testing.T) {
	out := `/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk4 on /Volumes/akasha-sessions (hfs, local, nodev, nosuid, noowners, mounted by someone)
/dev/disk6s1 on /Volumes/Obsidian 1.12.7 (apfs, local, read-only)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
`
	for _, tc := range []struct {
		mountpoint string
		wantDev    string
		wantOK     bool
	}{
		{"/Volumes/akasha-sessions", "/dev/disk4", true},
		{"/Volumes/Obsidian 1.12.7", "/dev/disk6s1", true},
		{"/", "/dev/disk3s1s1", true},
		{"/dev", "devfs", true},
		{"/Volumes/akasha-session", "", false},
		{"/Volumes/akasha-sessions/sub", "", false},
		{"/Volumes", "", false},
	} {
		dev, ok := mountEntryDevice(out, tc.mountpoint)
		if ok != tc.wantOK || dev != tc.wantDev {
			t.Errorf("mountEntryDevice(%q) = %q, %v; want %q, %v", tc.mountpoint, dev, ok, tc.wantDev, tc.wantOK)
		}
	}

	if _, ok := mountEntryDevice("", "/Volumes/akasha-sessions"); ok {
		t.Error("empty mount output reported a mount")
	}
}

// The RAM disk path shells out to fixed absolute paths; if the OS moves them the
// daemon must be updated rather than silently falling back to PATH.
func TestSystemToolsExistDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("RAM disk support is macOS-only")
	}
	for _, bin := range []string{binHdiutil, binDiskutil, binMount} {
		fi, err := os.Stat(bin)
		if err != nil {
			t.Errorf("%s: %v", bin, err)
			continue
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable", bin)
		}
	}
}
