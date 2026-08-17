package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/inferlabshq/akasha/daemon/internal/publisher"
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
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "akasha %s\n", Version())
		fmt.Fprintf(w, "  %s/%s, built with %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())

		// The official trust root is COMPILED IN (//go:embed official.pub), so
		// whether signed bundles can be verified is a property of this binary,
		// not of anything installed later. Reporting it here makes it checkable:
		// the release pipeline asks the binary it just built, so CI and the
		// verifier cannot disagree about what "configured" means.
		if publisher.OfficialConfigured() {
			fmt.Fprintln(w, "  official trust root: present (signed bundles verify without manual approval)")
		} else {
			fmt.Fprintln(w, "  official trust root: NOT CONFIGURED — this build cannot verify official")
			fmt.Fprintln(w, "    signatures, so every provider needs `akasha template trust`, and needs it")
			fmt.Fprintln(w, "    again after any release that edits it. Expected for source builds.")
		}
		return nil
	},
}
