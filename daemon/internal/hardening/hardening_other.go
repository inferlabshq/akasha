//go:build !linux && !darwin

package hardening

// apply does nothing on a platform this package has not been written for.
// Reporting that plainly beats returning an empty Result, which would read as
// "hardened" in the daemon's startup line.
func apply() Result {
	return Result{Skipped: []string{"no hardening implemented for this platform"}}
}
