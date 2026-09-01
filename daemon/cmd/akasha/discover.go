package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

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
		// Discovery reads every credential file this machine has and copies what
		// it finds into the vault. That is a human act, and the same one
		// `akasha protect` already refuses to perform on an agent's say-so.
		//
		// It has to be refused rather than merely checked, because there is no
		// check that works: discovery believes the disk, and an agent that can
		// write ~/.env or ~/.aws/credentials can put anything it likes where
		// discovery will find it and vault it under the human's names. The
		// daemon cannot tell those bytes from the user's own.
		//
		// Refusing here also retires the provisioning exemption on the daemon
		// side, which was a declared and therefore forgeable identity. An
		// exemption that nothing legitimate needs is only a hole.
		//
		// What this does NOT stop, stated plainly because it was once claimed
		// otherwise: an agent can still write a file and wait for the human to
		// run discovery. The review listing catches that only when the planted
		// value COLLIDES with one the user already has — the shadow warning
		// needs two copies to compare. For a provider the user does not already
		// own, and for aws/git/ssh where an agent can overwrite the
		// top-precedence file in place, a planted finding is indistinguishable
		// from a real one, and --yes prints no listing at all. Reading
		// credentials off disk means trusting the disk; this narrows who may
		// act on it, not what it means.
		// --dry-run is exempt, and has to be: the refusal below tells the reader
		// to run it, and the guard sat ABOVE the dry-run branch, so following
		// akasha's own advice hit the same wall. An agent then loops. A dry run
		// writes nothing and prints field NAMES only, so there is nothing here
		// for the guard to protect.
		agentSession := os.Getenv("AKASHA_AGENT_ID") != "" || os.Getenv("AKASHA_AGENT_KEY") != ""
		if id := os.Getenv("AKASHA_AGENT_ID"); agentSession && !discoverDryRun {
			return fmt.Errorf("`akasha discover` copies credentials off this machine's disk into the vault, "+
				"so it is run by the person at the keyboard — not from inside an agent session (this one "+
				"is %s).\n\n"+
				"  Run this in your own terminal:\n      akasha discover %s\n\n"+
				"  Nothing has been changed. To see what it WOULD take without writing anything:\n"+
				"      akasha discover %s --dry-run",
				agentSessionName(id), strings.Join(args, " "), strings.Join(args, " "))
		}

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
	fmt.Print(provision.ReviewWith(findings, reviewContext()))

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
	var failed, refused int
	for _, f := range findings {
		if err := p.VaultFinding(f.Provider, f.Instance, f.Fields, f.Source); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s:%s: %v\n", f.Provider, f.Instance, err)
			failed++
			// A 4xx is the daemon answering, not the daemon being absent.
			if s := err.Error(); strings.Contains(s, "returned 40") || strings.Contains(s, "returned 41") {
				refused++
			}
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
		// Two very different causes, and guessing the wrong one sends the user
		// somewhere useless. A refusal means the daemon answered — it is
		// running, and it said no for a reason already printed above each ✗.
		// Telling that user to start the daemon wasted the one line they read.
		if refused > 0 && refused == failed {
			return fmt.Errorf("%d of %d credential(s) were refused by the daemon — the reason is on each line above",
				failed, len(findings))
		}
		return fmt.Errorf("%d of %d credential(s) could not be vaulted (if the daemon is not running, `akasha start`)",
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

// reviewContext gathers what the listing needs to mark a finding as unusual:
// which provider:instance pairs are already vaulted, and the clock.
//
// Best-effort by design. Discovery must keep working when the daemon is not up
// — that is its first-run case — so a failure here costs the marks and nothing
// else. An empty Known set marks nothing rather than marking EVERYTHING new,
// because a listing where every line is flagged has taught the reader to ignore
// the flag before they reach the end of it.
func reviewContext() provision.ReviewContext {
	ctx := provision.ReviewContext{Now: time.Now()}
	resp, err := daemonGet(socketPath, "/label/list?prefix=")
	if err != nil {
		return ctx
	}
	var names []string
	if err := json.Unmarshal([]byte(resp), &names); err != nil {
		return ctx
	}
	known := make(map[string]bool, len(names))
	for _, n := range names {
		known[n] = true
	}
	ctx.Known = known
	return ctx
}
