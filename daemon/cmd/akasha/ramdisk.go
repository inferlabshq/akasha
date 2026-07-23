package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/assume"
)

const ramMountPoint = "/Volumes/akasha-sessions"

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

	// Reuse an existing mount if a prior daemon left one.
	if isMountedDarwin(ramMountPoint) {
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
	return func() { exec.Command("hdiutil", "detach", dev).Run() }
}

// createRAMDiskDarwin attaches an MB-sized RAM disk and mounts it as an HFS+
// volume at ramMountPoint, returning the /dev/diskN node for later detach.
func createRAMDiskDarwin(mb int) (dev string, err error) {
	sectors := mb * 2048 // 512-byte sectors: 1 MB = 2048 sectors
	out, err := exec.Command("hdiutil", "attach", "-nomount", fmt.Sprintf("ram://%d", sectors)).Output()
	if err != nil {
		return "", err
	}
	dev = strings.TrimSpace(string(out))
	// erasevolume formats AND mounts at /Volumes/<name>.
	if err := exec.Command("diskutil", "erasevolume", "HFS+", "akasha-sessions", dev).Run(); err != nil {
		exec.Command("hdiutil", "detach", dev).Run()
		return "", err
	}
	return dev, nil
}

func isMountedDarwin(mountpoint string) bool {
	out, err := exec.Command("mount").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), " on "+mountpoint+" ")
}
