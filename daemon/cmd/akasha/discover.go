package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/provision"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var discoverCmd = &cobra.Command{
	Use:   "discover [provider|all]",
	Short: "Discover credentials on this machine and vault them",
	Long: `Scan the locations your provider templates declare and vault what is found.

Every provider is discovered the same way: by the ` + "`discover`" + ` block in its
template. Run ` + "`akasha template explain <provider>`" + ` to see exactly which
files a provider reads — that block is the complete list.

  akasha discover all             # every trusted provider
  akasha discover aws             # one provider
  akasha discover all --dry-run   # show what would be vaulted, change nothing
  akasha discover all --yes       # vault without asking

Without a terminal to prompt on — CI, a script, an agent — nothing is vaulted
unless --yes says so.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// A dry run must not reach purgeOrphans either: it deletes unreachable
		// credential chains, which is a write.
		if !discoverDryRun {
			defer purgeOrphans()
		}
		target := strings.ToLower(args[0])

		findings := template.DiscoverUser(trust.ApprovedFunc())
		if target != "all" {
			var filtered []template.Finding
			for _, f := range findings {
				if f.Provider == target {
					filtered = append(filtered, f)
				}
			}
			if len(filtered) == 0 {
				return fmt.Errorf("no credentials found for provider %q.\n"+
					"Check that its template is trusted (`akasha template list`) and that its\n"+
					"discover block names a location that exists (`akasha template explain %s`)",
					target, target)
			}
			findings = filtered
		}
		if len(findings) == 0 {
			fmt.Println("No credentials found.")
			fmt.Println("Locations searched are declared by each provider's discover block — see `akasha template list`.")
			return nil
		}
		return reviewAndVault(findings, discoverYes)
	},
}

// reviewAndVault shows what was found and vaults the selection.
//
// The listing and the interactive choice used to exist only for AWS, inside its
// hand-written scanner; every other provider was vaulted silently and without
// asking. Both now apply to every provider, because "here is what I found on
// your machine, which of it do you want stored?" is not an AWS-specific
// question.
func reviewAndVault(findings []template.Finding, autoYes bool) error {
	fmt.Print(provision.Review(findings))

	// Checked before anything else so no path can reach a write.
	if discoverDryRun {
		fmt.Println("--dry-run: nothing vaulted.")
		return nil
	}

	if autoYes {
		return vaultFindings(findings)
	}

	// No terminal, no --yes: vault NOTHING.
	//
	// This branch used to do the opposite — it vaulted everything and said so on
	// stdout — and the honesty of the message did not make it safe. The trigger
	// is not piping, it is any stdin that is not a tty: CI, a Makefile, `curl |
	// sh`, `docker run` without -t, and an agent running `akasha`, which is our
	// own stated audience. `echo n | akasha discover all` vaulted 32 credentials
	// on the test machine; "no" was one of the inputs that did it.
	//
	// Nor is the piped input read instead: under `curl | sh` stdin IS the
	// installer script, and consuming a line of it to answer a prompt the author
	// never wrote is its own bug. Consent cannot be inferred from the absence of
	// a terminal, so it has to be spelled: --yes.
	//
	// It exits non-zero rather than 0, because the caller asked for credentials
	// to be vaulted and none were. A green exit over an unchanged vault is how a
	// provisioning script ends up believing it is done.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("nothing vaulted: no terminal to confirm on.\n" +
			"Vaulting credentials is not something to do on a machine's behalf without being asked.\n" +
			"  akasha discover all --dry-run   # inspect, write nothing\n" +
			"  akasha discover all --yes       # vault everything listed above")
	}

	fmt.Print("Vault all? [y/N] or enter numbers (e.g. 1,3): ")
	input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch input = strings.TrimSpace(strings.ToLower(input)); input {
	case "y", "yes":
		return vaultFindings(findings)
	case "", "n", "no":
		fmt.Println("Nothing vaulted.")
		return nil
	}

	var selected []template.Finding
	for _, part := range strings.Split(input, ",") {
		var idx int
		fmt.Sscanf(strings.TrimSpace(part), "%d", &idx)
		if idx >= 1 && idx <= len(findings) {
			selected = append(selected, findings[idx-1])
		}
	}
	if len(selected) == 0 {
		fmt.Println("Nothing selected.")
		return nil
	}
	return vaultFindings(selected)
}

func vaultFindings(findings []template.Finding) error {
	key, _ := callerKey()
	p := provision.NewSocket(socketPath, "akasha-discover").WithKey(key)
	var failed int
	for _, f := range findings {
		if err := p.VaultFinding(f.Provider, f.Instance, f.Fields, f.Source); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s:%s: %v\n", f.Provider, f.Instance, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s:%s (%s) → vaulted\n", f.Provider, f.Instance, f.Source)
	}
	// A per-credential ✗ on stderr and then exit 0 reads as success to
	// everything that is not a human: `akasha discover all --yes` in a
	// provisioning script could fail on every single credential — the usual
	// cause being a daemon that is not running — and still leave a green build
	// over an empty vault. The ticks are for the human; the status is for the
	// script, and it has to reflect what actually reached the vault.
	if failed > 0 {
		return fmt.Errorf("%d of %d credential(s) could not be vaulted (is the daemon running? try `akasha start`)",
			failed, len(findings))
	}
	return nil
}

// purgeOrphans asks the daemon to garbage-collect credential chains orphaned by
// a previous discovery run, keeping the vault from growing on every re-scan.
// Best-effort: discovery still succeeds if the purge call fails.
func purgeOrphans() {
	daemonPost(socketPath, "/vault/purge", map[string]interface{}{})
}
