package main

import (
	"fmt"
	"github.com/inferlabshq/akasha/daemon/internal/buildinfo"
	"runtime"

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
// Version stamps first, then reads. Idempotent, and deliberately not reliant
// on initialization order: rootCmd is a package-level var whose initializer
// calls this, and because the read goes through another package Go sees no
// dependency on the stamping initializer below and orders rootCmd first by
// file name. Stamping here makes the dependency explicit in the only place
// that matters.
func Version() string {
	buildinfo.Set(version)
	return buildinfo.Version()
}

// The ldflag lands in main.version because that is what install.sh and the
// release workflow stamp; this hands it to the package the daemon, the audit
// log and the MCP server can actually import.
//
// A package-level var initializer as well, so the daemon-side readers of
// buildinfo (health, audit, MCP) see the stamp even on a path that never
// called Version(). Var initializers run before every init() in the package;
// this one still runs after main.go's rootCmd initializer, which is why
// Version() also stamps on its own.
var _ = func() struct{} { buildinfo.Set(version); return struct{}{} }()

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
		// The skew this command's own help describes, finally detectable: ask
		// the daemon, if there is one, which build it is running.
		if resp, err := daemonGet(socketPath, "/health"); err == nil {
			reportVersionSkew(w, resp, Version())
		}

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
