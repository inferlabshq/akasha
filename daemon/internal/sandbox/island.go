package sandbox

import (
	"os"
	"strings"
)

// An ISLAND is a directory replaced wholesale by a tmpfs, with the entries that
// were there at launch mounted back one at a time. What it buys is the thing a
// per-path mask structurally cannot give: a name that does not exist yet is
// covered, because there is nothing at that name to reach.
//
// This package spent four rewrites trying to answer "can a mount be placed at
// p?" — denyTargetPlaceable and its ancestors. The question has no good answer
// for /run. Nothing there is creatable by the user akasha runs as, so every
// version of that predicate correctly reported "no", and every version therefore
// emitted NO MASK AT ALL for two paths that matter:
//
//   - /run/docker.sock, when dockerd starts after the sandbox does. The docker
//     socket is root-equivalent: a container can bind-mount the host's / and read
//     the vault. DenyDeputies exists to close it, and on a machine where docker
//     started later it closed nothing.
//   - /run/user/<uid>, when logind creates the session after launch. That is the
//     whole session-bus and keyring surface DenyKeychain is about.
//
// Both are unmaskable BY the old approach and trivially covered by this one: the
// island's tmpfs is placed on /run, which always exists, and neither name is
// rebound.
//
// RESIDUAL, stated because a sandbox whose gaps are unwritten is a sandbox
// nobody can audit: the island freezes /run's TOP LEVEL only. A rebound entry is
// a live bind, so files created inside /run/systemd after launch are still
// visible. That is deliberate — those are the paths a working machine needs (DNS
// through /run/systemd/resolve, the system bus, nss sockets) and freezing them
// would break the child for no credential-surface gain.
//
// The island NARROWS nothing that allow-by-default granted: every entry present
// at launch is mounted back read-write, exactly as --dev-bind / / had it. The
// only things it takes away are the names deliberately excluded.
//
// ── Why only /run, and why $HOME is not sealed read-only ──────────────────
//
// A design review proposed extending this to $HOME, $HOME/.config and
// $HOME/.local/share, and separately mounting $HOME read-only with a
// --sandbox-home=open escape hatch. Both were declined, on measurement rather
// than taste, and this is the note for whoever proposes them again.
//
// The islands were declined because the per-path masks already hold there.
// Measured on ubuntu 24.04 as uid 1001 against real bwrap, each probe paired
// with a control that leaked: ~/.config/gh, ~/.local/share/keyrings and
// ~/.netrc created MID-RUN by a process outside the sandbox all stayed masked,
// because $HOME has a writable ancestor chain and denyTargetPlaceable puts the
// mask down at launch. /run is different, and is the only place that is: it is
// root-owned, so nothing could be placed there at all, which is why a
// docker.sock or a session directory appearing later was reachable.
//
// A child also cannot escape a mask from inside. rm, mv -f, rmdir and mv of a
// masked directory all return EBUSY; a symlink to one resolves to the mask;
// renaming the mask's PARENT succeeds and gains nothing, because the mount
// follows the dentry and the secret stays underneath it. The review's premise
// that `mv -f` defeats a /dev/null file mask does not reproduce.
//
// The read-only seal was declined for a different reason: the security case did
// not survive the measurement above, and the usability cost is unchanged — a
// first `go install` inside a run fails with EROFS. Nobody on the review
// actually proposed adopting it either; it was raised and flagged as the one
// contentious default. Sealing $HOME to prevent writes akasha does not care
// about, in order to close a leak that measurement says is already closed, is
// friction bought with nothing.
//
// What would reopen either: a demonstrated leak inside $HOME that a per-path
// mask cannot close. Until then this stays one island, for the one directory
// that needs it.

const islandRunRoot = "/run"

// islandPlan is what an island covers, kept so the deny loop can tell the two
// cases apart: a path under an EXCLUDED entry does not exist inside and needs no
// further mask, while a path under a REBOUND entry is live host content and
// still needs its own.
//
// Getting that distinction wrong in either direction is a real bug — over-broad
// and a nested deny is silently dropped, under-broad and bwrap is asked to mount
// twice at one target.
type islandPlan struct {
	root     string
	excluded map[string]bool // top-level names deliberately not rebound
	args     []string
}

// covers reports whether p is already masked by this island.
func (ip islandPlan) covers(p string) bool {
	if ip.root == "" {
		return false
	}
	if p == ip.root {
		return true
	}
	rest, ok := strings.CutPrefix(p, ip.root+"/")
	if !ok {
		return false
	}
	return ip.excluded[strings.SplitN(rest, "/", 2)[0]]
}

// planRunIsland builds the /run island for a spec, or a zero plan when /run
// cannot be enumerated — in which case the caller falls back to the per-path
// masks, which is what shipped before this existed.
func planRunIsland(spec Spec) islandPlan {
	excluded := map[string]bool{
		// The session runtime directory: the bus, the keyring control socket,
		// the ssh-agent socket and akasha's own session credential dir all live
		// under /run/user/<uid>.
		//
		// Excluded WHOLESALE rather than per-uid, and that is the point. A mask
		// on this user's /run/user/<uid> does nothing about a /run/user/<uid>
		// that logind has not created yet — the case no predicate could reach.
		// Leaving the whole directory out of the rebind covers every session,
		// present and future, without asking who owns what.
		//
		// bwrap binds RECURSIVELY, so rebinding /run/user would have dragged
		// every live session tmpfs back in with it and undone the mask in one
		// argument.
		"user": true,
	}
	// A top-level entry the spec denies outright is left out instead of being
	// covered by a bind of /dev/null. Absent beats empty: /dev/null over a name
	// masks that INODE, and the socket's owner can unlink and recreate it beside
	// the mask — which is exactly how the session bus came back to life inside a
	// running sandbox and returned the vault key.
	exclude := func(p string) {
		if rest, ok := strings.CutPrefix(p, islandRunRoot+"/"); ok {
			// Only an EXACT top-level match. A deny nested deeper must not
			// remove its whole parent: /run/systemd would take DNS with it.
			if !strings.Contains(rest, "/") {
				excluded[rest] = true
			}
		}
	}
	for _, r := range spec.Deny {
		if !r.appliesTo("linux") {
			continue
		}
		for _, t := range mountTargets(r.Path) {
			exclude(t)
		}
	}
	if spec.DenyDeputies {
		for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
			for _, t := range mountTargets(p) {
				exclude(t)
			}
		}
	}
	if spec.DenyKeychain {
		for _, p := range append(linuxKeyringPaths(), linuxSecretServicePaths()...) {
			for _, t := range mountTargets(p) {
				exclude(t)
			}
		}
	}

	entries, err := os.ReadDir(islandRunRoot)
	if err != nil {
		return islandPlan{} // not enumerable: fall back to per-path masks
	}
	return islandPlan{
		root:     islandRunRoot,
		excluded: excluded,
		args:     islandArgs(islandRunRoot, excluded, entries, os.Readlink),
	}
}

// islandArgs renders the tmpfs and one rebind per kept entry.
//
// os.ReadDir sorts by filename, so the argv is deterministic for a given
// directory — a property the tests depend on and a reader diffing two profiles
// needs.
func islandArgs(root string, excluded map[string]bool, entries []os.DirEntry, readlink func(string) (string, error)) []string {
	a := []string{"--tmpfs", root}
	for _, e := range entries {
		name := e.Name()
		if excluded[name] || !safeIslandName(name) {
			continue
		}
		p := root + "/" + name

		// A SYMLINK is recreated as a symlink, never bound.
		//
		// --ro-bind FOLLOWS the link and mounts what it points at, under the
		// link's name. On a host where /run/foo points into a denied directory
		// that hands the denied content back through the island — the same
		// class of bug as the allow-back that resolved into ~/.aws, which this
		// package has already shipped once. --symlink recreates the NAME, and
		// the name then resolves inside the sandbox, against the masks.
		if e.Type()&os.ModeSymlink != 0 {
			target, err := readlink(p)
			if err != nil || target == "" || !safeSymlinkTarget(target) {
				continue
			}
			a = append(a, "--symlink", target, p)
			continue
		}

		// --bind, not --ro-bind: allow-by-default already granted write here and
		// an island must not narrow what it is only meant to freeze. --bind-try
		// because enumeration and launch are two moments, and a tmpfiles.d sweep
		// between them should not abort the run.
		a = append(a, "--bind-try", p, p)
	}
	return a
}

// safeIslandName rejects a directory entry that should not become argv.
//
// These names come from readdir on a real directory, so unlike a Spec path they
// cannot be attacker-chosen text — and on Linux each becomes one literal argv
// element, with no shell and no generated program anywhere in the path. This is
// belt-and-braces for the pathological filename rather than a security boundary;
// the macOS renderer is where a path becomes a program, and it never sees these.
func safeIslandName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return false
		}
	}
	return true
}

// safeSymlinkTarget rejects a link target that cannot be passed through argv.
// A target is not required to be absolute — /run is full of relative ones.
func safeSymlinkTarget(t string) bool {
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] == 0x7f {
			return false
		}
	}
	return true
}
