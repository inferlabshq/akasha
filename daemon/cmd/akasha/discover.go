package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
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
  akasha discover all --dry-run   # show what would be vaulted, change nothing`,
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
	fmt.Printf("Found %d credential(s):\n\n", len(findings))
	for i, f := range findings {
		fmt.Printf("  [%d] %s:%s\n", i+1, f.Provider, f.Instance)
		fmt.Printf("      source: %s\n", f.Source)
		fmt.Printf("      fields: %s\n\n", describeFields(f.Fields))
	}

	// Checked before anything else so no path can reach a write.
	if discoverDryRun {
		fmt.Println("--dry-run: nothing vaulted.")
		return nil
	}

	// Non-interactive (piped, CI, --yes): vault everything.
	//
	// SAY SO. This is the branch that surprises people: piping anything into
	// `akasha discover` — including a "no" — skips the prompt entirely and
	// vaults, because there is no terminal to prompt on. Silence made that
	// indistinguishable from a dry run right up until the vault had changed.
	if autoYes || !term.IsTerminal(int(os.Stdin.Fd())) {
		if !autoYes {
			fmt.Println("Non-interactive input: vaulting everything found (use --dry-run to inspect without writing).")
		}
		return vaultFindings(findings)
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

// describeFields summarises a finding without printing any secret: field names,
// and for each whether a value was actually found. Missing pieces are what the
// user needs to see — a credential half-discovered is the case worth noticing.
func describeFields(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func vaultFindings(findings []template.Finding) error {
	p := provision.NewLocal("akasha-discover")
	for _, f := range findings {
		if err := p.VaultFinding(f.Provider, f.Instance, f.Fields, f.Source); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s:%s: %v\n", f.Provider, f.Instance, err)
			continue
		}
		fmt.Printf("  ✓ %s:%s (%s) → vaulted\n", f.Provider, f.Instance, f.Source)
	}
	return nil
}

// purgeOrphans asks the daemon to garbage-collect credential chains orphaned by
// a previous discovery run, keeping the vault from growing on every re-scan.
// Best-effort: discovery still succeeds if the purge call fails.
func purgeOrphans() {
	daemonPost(socketPath, "/vault/purge", map[string]interface{}{})
}
