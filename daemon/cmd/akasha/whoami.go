package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// whoamiJSON prints the raw daemon payload instead of the table, for scripts.
var whoamiJSON bool

// identityReply mirrors the /identity response.
type identityReply struct {
	Provider  string            `json:"provider"`
	Profile   string            `json:"profile"`
	Facts     map[string]string `json:"facts"`
	Source    string            `json:"source"`
	Offline   bool              `json:"offline"`
	Contract  string            `json:"contract"`
	DerivedAt string            `json:"derived_at"`
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami [provider:profile]",
	Short: "Show which account/principal a vaulted credential belongs to",
	Long: `Show the non-secret identity behind a vaulted credential — which AWS account,
which principal — without assuming it, using it, or making a network call.

This is the DESCRIBE path. Answering "which account is this?" used to require
assuming the credential and calling the provider's API, which also meant the
question became unanswerable the moment the keys were deactivated. The facts
here are derived locally from the credential material, so they keep working on
a credential that no longer authenticates.

Nothing secret is printed, and nothing is written into your session.

  akasha whoami                 # every profile that can be described
  akasha whoami aws:default     # one profile`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()

		var targets []string
		if len(args) == 1 {
			if !strings.Contains(args[0], ":") {
				return fmt.Errorf("expected provider:profile (e.g. aws:default), got %q", args[0])
			}
			targets = []string{args[0]}
		} else {
			var err error
			if targets, err = describableTargets(); err != nil {
				return err
			}
			if len(targets) == 0 {
				fmt.Fprintln(w, "Nothing vaulted yet — run `akasha discover all` or `akasha put <provider>:<name>`.")
				return nil
			}
		}

		// Collect first, print second: a bare `whoami` over several profiles
		// should not interleave results with per-profile errors.
		var failures []string
		var replies []identityReply
		for _, t := range targets {
			provider, profile, _ := strings.Cut(t, ":")
			rep, err := fetchIdentity(provider, profile)
			if err != nil {
				failures = append(failures, fmt.Sprintf("  %s: %s", t, oneLineErr(err)))
				continue
			}
			replies = append(replies, *rep)
		}

		if whoamiJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(replies); err != nil {
				return err
			}
		} else {
			for i, rep := range replies {
				if i > 0 {
					fmt.Fprintln(w)
				}
				printIdentity(w, rep)
			}
		}

		// An explicit single target that failed is the command failing; in a
		// sweep it is one profile that could not be described, which is worth
		// reporting but must not mask the ones that worked.
		if len(failures) > 0 {
			if len(targets) == 1 {
				return fmt.Errorf("%s", strings.TrimSpace(failures[0]))
			}
			fmt.Fprintf(w, "\nCould not describe:\n%s\n", strings.Join(failures, "\n"))
		}
		return nil
	},
}

// describableTargets lists every vaulted provider:profile pair, so a bare
// `whoami` covers what `list` shows.
func describableTargets() ([]string, error) {
	resp, err := daemonGet(socketPath, "/label/list?prefix=")
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable: %w", err)
	}
	var names []string
	if err := json.Unmarshal([]byte(resp), &names); err != nil {
		return nil, fmt.Errorf("unexpected response: %s", resp)
	}
	var out []string
	for _, n := range names {
		if strings.Contains(n, ":") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

func fetchIdentity(provider, profile string) (*identityReply, error) {
	resp, err := daemonGet(socketPath,
		fmt.Sprintf("/identity?provider=%s&profile=%s", provider, profile))
	if err != nil {
		return nil, err
	}
	var rep identityReply
	if err := json.Unmarshal([]byte(resp), &rep); err != nil {
		return nil, fmt.Errorf("unexpected response: %s", resp)
	}
	return &rep, nil
}

// factOrder puts the fact people came for first; anything a future contract
// adds is appended alphabetically rather than dropped.
//
// Note what is absent: the access key id. It is derivation input, not a fact,
// and printing it would scatter half the credential pair through terminals,
// scrollback, and CI logs for no benefit.
var factOrder = []string{"account_id", "principal", "arn", "alias", "key_type"}

func printIdentity(w interface{ Write([]byte) (int, error) }, rep identityReply) {
	fmt.Fprintf(w, "%s:%s\n", rep.Provider, rep.Profile)

	seen := map[string]bool{}
	var keys []string
	for _, k := range factOrder {
		if _, ok := rep.Facts[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range rep.Facts {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	keys = append(keys, rest...)

	width := 0
	for _, k := range keys {
		if len(k) > width {
			width = len(k)
		}
	}
	for _, k := range keys {
		fmt.Fprintf(w, "  %-*s  %s\n", width, k, rep.Facts[k])
	}

	// How the answer was obtained belongs next to the answer: a locally decoded
	// account number and one confirmed by the provider are not the same claim.
	if rep.Source != "" {
		fmt.Fprintf(w, "  %-*s  %s\n", width, "source", rep.Source)
	}
}

// oneLineErr flattens a daemon error for the per-profile failure list.
func oneLineErr(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

func init() {
	whoamiCmd.Flags().BoolVar(&whoamiJSON, "json", false, "Print the raw identity payload")
}
