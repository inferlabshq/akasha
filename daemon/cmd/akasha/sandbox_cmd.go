package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/sandbox"
)

// `akasha sandbox doctor` answers one question, on this machine, without
// starting an agent: what does the sandbox actually cover here?
//
// Everything else that could answer it needs a running daemon and a registered
// agent, because `akasha run --print-profile` is a run that stops early. That is
// the wrong shape for the two moments the question gets asked — a user reporting
// "it will not start", and CI on a machine shape nobody has locally — and it is
// the shape that let three rounds of verification pass while the sandbox was
// broken for every non-root user.
//
// The output is deliberately paste-able into a bug report: it names paths, not
// secrets, and the profile it prints is the same one a run would use.
var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Inspect and verify the OS sandbox `akasha run` uses",
}

var sandboxDoctorProfile bool

var sandboxDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check that the sandbox works on this machine, and report what it covers",
	Long: `Builds the profile 'akasha run' would use on THIS machine, reports what each
rule is enforced by — and, more importantly, what it is not — then runs the
sandbox against itself and reports whether it is genuinely enforcing.

Needs no daemon and no agent. Exits non-zero if the sandbox could not be
verified, so it can be used as a CI gate.

  akasha sandbox doctor              # verdict plus the coverage table
  akasha sandbox doctor --profile    # ...and the full launcher profile`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()

		// Step 1: can this machine sandbox at all? A missing bwrap or a kernel
		// that refuses user namespaces is a different problem from a profile
		// that does not enforce, and it needs different advice.
		if err := sandbox.Available(); err != nil {
			fmt.Fprintf(w, "✗ no sandbox available\n\n%s\n", sandbox.Explain(err))
			return fmt.Errorf("sandbox unavailable on this machine")
		}
		fmt.Fprintln(w, "✓ sandbox backend available")

		// Step 2: the real surface. A temp run directory stands in for the one
		// a run would create; nothing in the deny set depends on its contents.
		runDir, err := os.MkdirTemp("", "akasha-doctor-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(runDir)

		spec := sandbox.Surface(defaultDataDir(), runDir, nil, nil)
		if sock := socketPath; sock != "" {
			if _, err := os.Stat(sock); err == nil {
				spec = spec.AllowSocketPath(sock)
			}
		}

		profile, err := sandbox.Describe(spec)
		if err != nil {
			return fmt.Errorf("the profile could not be rendered: %w", err)
		}
		fmt.Fprintln(w)
		if sandboxDoctorProfile {
			fmt.Fprintln(w, profile)
		} else {
			// The coverage table only. It is the part a human reads; the argv
			// underneath it is for a maintainer.
			fmt.Fprintln(w, coverageOnly(profile))
			fmt.Fprintln(w, "  (--profile shows the full launcher command)")
		}

		// Step 3: prove it. This is the step that distinguishes "a profile was
		// generated" from "the profile is enforcing", and they look identical
		// from anywhere else.
		binary, err := os.Executable()
		if err != nil {
			return fmt.Errorf("cannot locate this binary to run the self-test: %w", err)
		}
		if err := sandbox.SelfTest(spec, binary); err != nil {
			fmt.Fprintf(w, "\n✗ the sandbox is NOT enforcing what the profile claims\n\n%v\n", err)
			return fmt.Errorf("sandbox self-test failed")
		}
		fmt.Fprintln(w, "\n✓ verified: the sandbox enforces this profile")
		return nil
	},
}

// coverageOnly keeps the leading comment block Plan.Describe emits and drops the
// launcher argv beneath it.
func coverageOnly(profile string) string {
	out := ""
	for _, line := range strings.Split(profile, "\n") {
		if len(line) > 0 && line[0] != '#' {
			break
		}
		out += line + "\n"
	}
	if out == "" {
		// macOS renders an SBPL profile, which has no plan block. Say so rather
		// than printing nothing, which would read as "nothing is covered".
		return "  (no coverage table on this platform — run with --profile to see the seatbelt rules)"
	}
	return out
}
