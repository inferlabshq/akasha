// Package hardening reduces what a same-uid observer can take out of the
// running daemon.
//
// The vault key is in this process's memory for as long as it runs — it has to
// be, since every brokered operation decrypts with it. Everything else akasha
// does about same-uid access happens at its own API, where policy and approvals
// live. None of that applies to a process that reads /proc/<pid>/mem or picks
// the key out of a core file, because such a process never calls the daemon at
// all.
//
// This does not make that impossible. It removes the cheap versions.
//
// Best-effort by design: a daemon that refuses to start because it could not
// lower a resource limit has turned a hardening measure into an outage. But it
// is never SILENT — a control that quietly did nothing is the failure this
// project keeps finding, so Apply reports what it managed and what it did not,
// and the caller says so.
package hardening

import "os"

// DisableEnv turns hardening off, for profiling or attaching a debugger to the
// daemon. Safe as an escape hatch: setting it requires controlling the
// environment the daemon is launched with, and anything that can do that can
// simply run its own daemon instead.
const DisableEnv = "AKASHA_NO_HARDENING"

// Result is what was applied and what was not, so neither is a guess.
type Result struct {
	Applied []string
	Skipped []string
}

// Summary is a one-line description for the daemon's startup output.
func (r Result) Summary() string {
	if len(r.Applied) == 0 {
		if len(r.Skipped) == 0 {
			return "none available on this platform"
		}
		return "NONE — " + join(r.Skipped)
	}
	s := join(r.Applied)
	if len(r.Skipped) > 0 {
		s += "; not applied: " + join(r.Skipped)
	}
	return s
}

func join(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// Apply hardens the current process. Call it before the vault key is loaded —
// a limit raised after the secret is in memory has already missed the window a
// crash could have used.
func Apply() Result {
	if os.Getenv(DisableEnv) != "" {
		return Result{Skipped: []string{"disabled by " + DisableEnv}}
	}
	return apply()
}
