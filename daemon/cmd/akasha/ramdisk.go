package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

const (
	ramMountPoint = "/Volumes/akasha-sessions"
	ramVolumeName = "akasha-sessions"
)

// These tools run with the daemon's own privileges, so they are named by
// absolute path: a PATH entry any local process can write would otherwise
// decide what "hdiutil" means. Same rule internal/resolve and internal/sandbox
// apply to the binaries they execute.
const (
	binHdiutil  = "/usr/bin/hdiutil"
	binDiskutil = "/usr/sbin/diskutil"
	binMount    = "/sbin/mount"
)

// setupSessionStorage points the assume package at a RAM-backed location so
// credential files never touch physical disk. On Linux the assume resolver
// already prefers tmpfs ($XDG_RUNTIME_DIR / /dev/shm), so this only does work
// on macOS, where it mounts a small RAM disk. Best-effort: on any failure it
// returns a no-op cleanup and assume falls back to ~/.akasha (0600 + TTL).
func setupSessionStorage() (cleanup func()) {
	noop := func() {}
	if runtime.GOOS != "darwin" {
		return noop // Linux: tmpfs auto-detected by the assume resolver
	}

	// Reuse an existing mount if a prior daemon left one — but only if it is
	// ours. /Volumes is a shared namespace and mounting is unprivileged, so the
	// name alone says nothing about who owns the storage underneath it.
	if _, mounted := mountedDeviceDarwin(ramMountPoint); mounted {
		if err := safeSessionDir(ramMountPoint); err != nil {
			// Unmounting a volume that may belong to another user is not ours
			// to do; take the documented fallback instead.
			fmt.Fprintf(os.Stderr, "akasha: %s is mounted but not safely ours (%v) — session files use ~/.akasha\n", ramMountPoint, err)
			return noop
		}
		assume.SetSessionBase(ramMountPoint)
		fmt.Fprintf(os.Stderr, "akasha: reusing RAM disk at %s\n", ramMountPoint)
		return noop
	}

	dev, err := createRAMDiskDarwin(64) // 64 MB is ample for credential files
	if err != nil {
		fmt.Fprintf(os.Stderr, "akasha: RAM disk unavailable (%v); session files use ~/.akasha\n", err)
		return noop
	}
	assume.SetSessionBase(ramMountPoint)
	fmt.Fprintf(os.Stderr, "akasha: credential files in RAM disk %s (never on SSD)\n", ramMountPoint)
	return func() { exec.Command(binHdiutil, "detach", dev).Run() }
}

// createRAMDiskDarwin attaches an MB-sized RAM disk and mounts it as an HFS+
// volume at ramMountPoint, returning the /dev/diskN node for later detach.
func createRAMDiskDarwin(mb int) (dev string, err error) {
	sectors := mb * 2048 // 512-byte sectors: 1 MB = 2048 sectors
	out, err := exec.Command(binHdiutil, "attach", "-nomount", fmt.Sprintf("ram://%d", sectors)).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("hdiutil attached no device")
	}
	dev = fields[0]
	detach := func() { exec.Command(binHdiutil, "detach", dev).Run() }

	// erasevolume formats AND mounts at /Volumes/<name>.
	if err := exec.Command(binDiskutil, "erasevolume", "HFS+", ramVolumeName, dev).Run(); err != nil {
		detach()
		return "", err
	}
	// When the name is taken the volume lands at "<name> 1" and ramMountPoint
	// still belongs to whoever got there first, so confirm the device before
	// anything is written through that path.
	if at, mounted := mountedDeviceDarwin(ramMountPoint); !mounted || at != dev {
		detach()
		return "", fmt.Errorf("volume did not mount at %s", ramMountPoint)
	}
	// A freshly erased HFS+ volume root is 0775 group staff, which on macOS is
	// every local account.
	if err := os.Chmod(ramMountPoint, 0o700); err != nil {
		detach()
		return "", err
	}
	if err := safeSessionDir(ramMountPoint); err != nil {
		detach()
		return "", err
	}
	return dev, nil
}

// safeSessionDir reports whether path is a real directory that only its owner —
// us — can write to. HFS+ RAM disks are mounted noowners, so the owner reported
// for the volume root is the user who mounted it; that is precisely the
// distinction between our RAM disk and a volume someone else parked under the
// same name to collect materialized credentials.
func safeSessionDir(path string) error {
	fi, err := os.Lstat(path) // Lstat: a symlink at the mount point is not a mount point
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("not a directory")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ownership unavailable")
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not %d", st.Uid, os.Getuid())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("mode %04o is group- or world-writable", perm)
	}
	return nil
}

// mountedDeviceDarwin returns the device mounted at mountpoint, if any.
func mountedDeviceDarwin(mountpoint string) (dev string, ok bool) {
	out, err := exec.Command(binMount).Output()
	if err != nil {
		return "", false
	}
	return mountEntryDevice(string(out), mountpoint)
}

// mountEntryDevice picks the device out of `mount` output, whose lines read
// "<dev> on <mountpoint> (opts)". Mount points may contain spaces, so the path
// is everything between " on " and the trailing option list rather than a
// whitespace field.
func mountEntryDevice(mountOutput, mountpoint string) (dev string, ok bool) {
	for _, line := range strings.Split(mountOutput, "\n") {
		i := strings.Index(line, " on ")
		if i < 0 {
			continue
		}
		rest := line[i+len(" on "):]
		j := strings.LastIndex(rest, " (")
		if j < 0 {
			continue
		}
		if rest[:j] == mountpoint {
			return line[:i], true
		}
	}
	return "", false
}
