package hardening

import "golang.org/x/sys/unix"

// apply on Linux does the two things that matter, in the order that matters.
//
// PR_SET_DUMPABLE=0 is the one with teeth. Opening /proc/<pid>/mem requires
// ptrace attach permission, and a non-dumpable process fails that check even
// for its own user — so the open is refused with EPERM rather than succeeding
// and letting the caller seek to a mapped address.
//
// Measured, because the mechanism is easy to describe wrongly: on a container
// with kernel.yama.ptrace_scope=0, a second process running as the same user
// opened the daemon's /proc/<pid>/mem successfully without this, and was
// refused with it. (The /proc/<pid> directory stayed owned by that user in both
// cases — the ownership reassignment proc(5) describes is not what does the
// work here, whatever else it applies to.)
//
// Without this, whether such a reader succeeds depends entirely on the
// machine's yama/ptrace_scope: Ubuntu ships 1 (descendants only), plenty of
// distros ship 0 (any same-uid process). A security property that varies by
// distro default is not a property.
//
// It also stops the kernel writing a core file for this process at all, which
// is the same protection RLIMIT_CORE gives — but the limit is set too, because
// dumpable can be raised again by the process itself and the limit cannot be
// raised past its own maximum once lowered.
func apply() Result {
	var r Result
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		r.Skipped = append(r.Skipped, "non-dumpable ("+err.Error()+")")
	} else {
		r.Applied = append(r.Applied, "non-dumpable")
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		r.Skipped = append(r.Skipped, "core dumps ("+err.Error()+")")
	} else {
		r.Applied = append(r.Applied, "core dumps off")
	}
	return r
}
