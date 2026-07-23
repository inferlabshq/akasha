package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var putStdin bool

var putCmd = &cobra.Command{
	Use:   "put <label> [FIELD ...]",
	Short: "Store a secret under a label so `assume` can use it",
	Long: `Vaults a secret that discovery didn't find, under a label you choose, so
it can be assumed later — including for providers assume doesn't natively
support, via the generic "env:" provider (field names become env vars).

Interactive (values are read without echo):

  akasha put env:stripe STRIPE_API_KEY
  akasha put env:db DATABASE_URL PGPASSWORD

Then use it:

  akasha exec --assume env:stripe -- ./charge.sh
  eval-style env vars are returned for any provider:profile.

Non-interactive (for agents/CI), pipe a JSON object of field→value:

  echo '{"STRIPE_API_KEY":"sk_live_..."}' | akasha put env:stripe --stdin`,
	Args: cobra.MinimumNArgs(1),
	RunE: runPut,
}

func runPut(cmd *cobra.Command, args []string) error {
	label := args[0]
	if !strings.Contains(label, ":") {
		return fmt.Errorf("label should be of the form provider:profile, e.g. env:stripe")
	}

	fields := map[string]string{}

	if putStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &fields); err != nil {
			return fmt.Errorf("--stdin expects a JSON object of field:value: %w", err)
		}
	} else {
		names := args[1:]
		if len(names) == 0 {
			return fmt.Errorf("name at least one field, e.g. akasha put env:stripe STRIPE_API_KEY")
		}
		for _, name := range names {
			fmt.Printf("Enter value for %s: ", name)
			val, err := readPassphrase()
			if err != nil {
				return err
			}
			if len(val) == 0 {
				return fmt.Errorf("empty value for %s", name)
			}
			fields[name] = string(val)
		}
	}

	provider, profile, _ := strings.Cut(label, ":")
	resp, err := daemonPost(socketPath, "/put", map[string]interface{}{
		"label":    label,
		"fields":   fields,
		"provider": provider,
		"profile":  profile,
	})
	if err != nil {
		return fmt.Errorf("store failed (is `akasha start` running?): %w", err)
	}
	if msg, ok := resp["error"].(string); ok && msg != "" {
		return fmt.Errorf("%s", msg)
	}

	fmt.Printf("✓ stored under %s\n", label)
	fmt.Printf("  assume it with:  akasha exec --assume %s -- <command>\n", label)
	return nil
}
