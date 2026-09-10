// Package buildinfo is the one place the running binary's version lives.
//
// It exists because the version was a variable in package main, stamped by
// -ldflags, and nothing under internal/ can import main. So the daemon's health
// endpoint could not say which build was answering, the audit log could not
// say which build wrote a line, and the MCP server announced a hardcoded
// "1.0.0" that no release ever updated. A leaf package with one setter, called
// from main's init before any goroutine starts, closes all three at once.
package buildinfo

import "runtime/debug"

var stamped = "dev"

// Set records the build version. Called once, from main, before anything
// that could read it runs.
func Set(v string) {
	if v != "" {
		stamped = v
	}
}

// Version returns the build version, falling back to the module's VCS stamp so
// a binary produced without the ldflag still identifies itself rather than
// claiming to be an anonymous "dev".
func Version() string {
	if stamped != "dev" {
		return stamped
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return stamped
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 12 {
				rev = s.Value[:12]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return stamped
	}
	return "dev-" + rev + dirty
}
