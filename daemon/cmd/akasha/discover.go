package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/inferlabshq/akasha/internal/discover"
	"github.com/inferlabshq/akasha/internal/provision"
	"github.com/inferlabshq/akasha/internal/template"
	"github.com/inferlabshq/akasha/internal/trust"
	"golang.org/x/term"
)

var discoverCmd = &cobra.Command{
	Use:   "discover [aws|ssh|git|all]",
	Short: "Discover credentials on this machine and vault them",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch strings.ToLower(args[0]) {
		case "aws":
			defer purgeOrphans()
			return discoverAWS(discoverYes)
		case "ssh":
			defer purgeOrphans()
			return discoverSSH()
		case "git":
			defer purgeOrphans()
			return discoverGit()
		case "all":
			defer purgeOrphans()
			discoverAWS(true) // non-interactive: vault everything
			discoverSSH()
			discoverGit()
			return discoverTemplates()
		default:
			// No native Go scanner for this provider — try template-driven
			// discovery (provider templates and discovery rules).
			defer purgeOrphans()
			return discoverTemplatesFor(strings.ToLower(args[0]))
		}
	},
}

// discoverTemplates runs template-driven discovery (user provider templates
// and kind:discovery rules) and vaults every finding.
func discoverTemplates() error {
	return vaultFindings(template.DiscoverUser(trust.ApprovedFunc()))
}

// discoverTemplatesFor restricts template discovery to one provider name.
func discoverTemplatesFor(provider string) error {
	var findings []template.Finding
	for _, f := range template.DiscoverUser(trust.ApprovedFunc()) {
		if f.Provider == provider {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		return fmt.Errorf("no findings for provider %q — native scanners: aws, ssh, git, all; or add a template/discovery rule in ~/.akasha/templates/", provider)
	}
	return vaultFindings(findings)
}

func vaultFindings(findings []template.Finding) error {
	p := provision.NewLocal("akasha-discover")
	for _, f := range findings {
		if err := p.VaultFinding(f.Provider, f.Instance, f.Fields, f.Source); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s:%s: %v\n", f.Provider, f.Instance, err)
			continue
		}
		fmt.Printf("  ✓ %s %s (%s) → vaulted\n", f.Provider, f.Instance, f.Source)
	}
	return nil
}

// purgeOrphans asks the daemon to garbage-collect credential chains orphaned by
// a previous discovery run, keeping the vault from growing on every re-scan.
// Best-effort: discovery still succeeds if the purge call fails.
func purgeOrphans() {
	daemonPost(socketPath, "/vault/purge", map[string]interface{}{})
}

// storeAndLabel vaults a credential map and labels it, returning the label token.
// Mirrors the setup wizard's behavior so labels have a uniform map shape.
func discoverSSH() error {
	fmt.Println("Scanning for SSH keys...")
	creds, err := discover.DiscoverSSH()
	if err != nil || len(creds) == 0 {
		fmt.Println("  No SSH private keys found in ~/.ssh")
		return nil
	}
	p := provision.NewLocal("akasha-discover")
	for _, c := range creds {
		if err := p.VaultSSH(c); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.Profile, err)
			continue
		}
		fmt.Printf("  ✓ ssh:%s (%s) → vaulted\n", c.Profile, c.KeyType)
	}
	return nil
}

func discoverGit() error {
	fmt.Println("Scanning for Git tokens...")
	creds, err := discover.DiscoverGit()
	if err != nil || len(creds) == 0 {
		fmt.Println("  No Git tokens found (SSH-based git access uses ssh: keys instead)")
		return nil
	}
	p := provision.NewLocal("akasha-discover")
	for _, c := range creds {
		if err := p.VaultGit(c); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.Profile, err)
			continue
		}
		fmt.Printf("  ✓ git:%s [%s] → vaulted\n", c.Profile, c.Redacted())
	}
	return nil
}

func discoverAWS(autoYes bool) error {
	fmt.Println("Scanning for AWS credentials...")
	fmt.Println()

	creds, err := discover.DiscoverAWS()
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	if len(creds) == 0 {
		fmt.Println("No AWS credentials found.")
		fmt.Println("Checked: ~/.aws/credentials, ~/.aws/config, environment variables, .env files, shell configs.")
		return nil
	}

	fmt.Printf("Found %d credential set(s):\n\n", len(creds))
	for i, c := range creds {
		hasSecret := c.SecretAccessKey != ""
		secretStatus := "✓ secret key present"
		if !hasSecret {
			secretStatus = "⚠  secret key not found (access key only)"
		}
		tokenStatus := ""
		if c.SessionToken != "" {
			tokenStatus = "  + session token"
		}
		fmt.Printf("  [%d] profile=%q\n", i+1, c.Profile)
		fmt.Printf("      source:     %s\n", c.FormatSource())
		fmt.Printf("      access key: %s\n", c.Redacted())
		fmt.Printf("      %s%s\n\n", secretStatus, tokenStatus)
	}

	// Non-interactive: vault everything found without prompting. Used by
	// `discover all`, `--yes`, or whenever stdin isn't a terminal (piped/CI).
	if autoYes || !term.IsTerminal(int(os.Stdin.Fd())) {
		return vaultAWSAll(creds)
	}

	// Ask which to vault.
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Vault all? [y/N] or enter numbers (e.g. 1,3): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	var selected []discover.AWSCredential
	switch input {
	case "y", "yes":
		selected = creds
	case "", "n", "no":
		fmt.Println("Nothing vaulted.")
		return nil
	default:
		for _, part := range strings.Split(input, ",") {
			var idx int
			fmt.Sscanf(strings.TrimSpace(part), "%d", &idx)
			if idx >= 1 && idx <= len(creds) {
				selected = append(selected, creds[idx-1])
			}
		}
		if len(selected) == 0 {
			fmt.Println("Nothing selected.")
			return nil
		}
	}

	return vaultAWSAll(selected)
}

// vaultAWSAll vaults every credential in the slice, reporting failures.
func vaultAWSAll(creds []discover.AWSCredential) error {
	fmt.Println()
	for _, c := range creds {
		if err := vaultAWSCredential(c); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ [%s] %s\n", c.Profile, err)
		}
	}
	return nil
}

func vaultAWSCredential(c discover.AWSCredential) error {
	if err := provision.NewLocal("akasha-discover").VaultAWS(c); err != nil {
		return err
	}
	fmt.Printf("  ✓ profile=%q [%s] → vaulted (aws:%s)\n\n", c.Profile, c.Redacted(), c.Profile)
	return nil
}
