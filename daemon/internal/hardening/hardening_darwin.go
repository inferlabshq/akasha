package hardening

import "golang.org/x/sys/unix"

// apply on macOS lowers RLIMIT_CORE and stops there.
//
// The Linux half has no analogue that can be reached without cgo: the
// equivalent, ptrace(PT_DENY_ATTACH), is not in x/sys for darwin, and the
// release pipeline cross-compiles this binary with CGO_ENABLED=0. Adding cgo
// for it would cost cross-compilation and a macOS release runner.
//
// It is a smaller gap than it sounds. Reading another process's memory here
// goes through task_for_pid, which macOS already refuses to an unprivileged
// same-uid caller without the debugger entitlement — so the platform provides
// by default roughly what PR_SET_DUMPABLE has to be asked for on Linux. Core
// files are the remaining route, and that is what this closes.
func apply() Result {
	var r Result
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		r.Skipped = append(r.Skipped, "core dumps ("+err.Error()+")")
	} else {
		r.Applied = append(r.Applied, "core dumps off")
	}
	r.Skipped = append(r.Skipped, "anti-ptrace (needs cgo; task_for_pid already restricted here)")
	return r
}
