package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=v0.1.0-alpha.3"
//
// install.sh derives it from `git describe` for source builds and the release
// workflow uses the tag. An unstamped build reports "dev".
//
// This exists because a security release is only useful if people can tell
// whether they are on it. Telling users "upgrade past the credential bypass in
// alpha.2" is not actionable when the binary cannot say which version it is —
// they cannot confirm the upgrade worked, and neither can anyone triaging a
// report.
var version = "dev"

// Version returns the build version, falling back to the module's VCS stamp.
//
// Go embeds the revision automatically for `go install`-style builds, so a
// binary produced without the ldflag still identifies itself rather than
// claiming to be an anonymous "dev".
func Version() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
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
		return version
	}
	return "dev-" + rev + dirty
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the akasha version",
	Long: `Print the version, so you can confirm which build is installed.

Worth checking after any security release: the daemon and the CLI are the same
binary, but a running daemon keeps the binary it started with, so an upgraded
CLI can report a version the daemon is not yet running. Restart the daemon
(or re-run the installer, which does) to be sure.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("akasha %s\n", Version())
		fmt.Printf("  %s/%s, built with %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	},
}
