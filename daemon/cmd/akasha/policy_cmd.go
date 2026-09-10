package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/policy"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Show the local retrieval policy (~/.akasha/policy.yaml)",
	Long: `Rules evaluated by the daemon before any secret reaches an agent —
on /retrieve, /assume, the credential helper, and /grant. First match wins;
effects are allow, deny, or ask (interactive approval, fail-closed).
Edits take effect immediately, no daemon restart needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := policy.DefaultPath()
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			fmt.Printf("No policy file at %s — all operations are allowed.\n", path)
			fmt.Println("Create one with `akasha policy init`.")
			return nil
		}
		if err != nil {
			return err
		}
		// TWO parsers on purpose, and the difference is the whole answer.
		//
		// Authoring is checked strictly, so a misspelled matcher is caught here
		// rather than silently doing nothing. But the DAEMON reads the same file
		// with ParseLenient, which tolerates an unknown matcher on a well-formed
		// rule and makes that rule fail closed instead of refusing the file.
		//
		// This command used to run only the strict parser and then announce
		// "the daemon is denying ALL operations until this parses", which stopped
		// being true when the lenient parser landed. Measured: with a misspelled
		// `provder:` key, validate said the daemon was denying everything while
		// the same session had `list`, `status` and unrelated assumes all
		// working. A validator that asserts another component's behaviour without
		// asking it is a guess presented as a diagnosis — and this one sends the
		// reader to fix an outage that is not happening.
		strict, serr := policy.Parse(data)
		lenient, lerr := policy.ParseLenient(data)
		fmt.Printf("Policy: %s\n\n%s\n", path, data)

		switch {
		case lerr != nil:
			// The daemon cannot read it either. This IS the total-denial case.
			fmt.Printf("⚠  INVALID — the daemon cannot parse this file, so it is denying ALL\n"+
				"   operations until it is fixed: %v\n", lerr)
			return nil
		case serr != nil:
			// The daemon runs this file; some rules just cannot be fully
			// evaluated. Say which way that falls, because the two effects are
			// opposite.
			fmt.Printf("⚠  NOT STRICTLY VALID — but the daemon DOES run this file: %v\n\n", serr)
			fmt.Println("   A rule the daemon cannot fully evaluate fails closed: it still matches")
			fmt.Println("   `deny` and `ask`, and it can no longer satisfy an `allow`. So the effect")
			fmt.Println("   is narrower access, not an outage — but a rule you meant to GRANT with")
			fmt.Println("   may have stopped granting. Fix the spelling.")
			fmt.Printf("\n   Parsed by the daemon as: %d rule(s), default %s.\n",
				len(lenient.Rules), lenient.Default)
			return nil
		}
		p := strict
		fmt.Printf("Valid: %d rule(s), default %s, ask timeout %ds.\n",
			len(p.Rules), p.Default, p.AskTimeoutSeconds)
		return nil
	},
}

var policyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a commented starter policy.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := policy.DefaultPath()
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists — edit it directly", path)
		}
		if err := os.MkdirAll(defaultDataDir(), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(policy.Starter), 0600); err != nil {
			return err
		}
		fmt.Printf("Wrote %s — active immediately, edit freely.\n", path)
		fmt.Println("Validate after editing with `akasha policy validate`.")
		return nil
	},
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check that policy.yaml parses (a broken file denies everything)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := policy.DefaultPath()
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			fmt.Printf("No policy file at %s — nothing to validate (all operations allowed).\n", path)
			return nil
		}
		if err != nil {
			return err
		}
		// Strict for authoring, lenient for what the DAEMON will actually do.
		// These diverge on purpose and the difference decides the answer, so
		// asking only one of them is how this command came to assert a total
		// outage that was not happening. See the same split in `akasha policy`.
		p, serr := policy.Parse(data)
		lenient, lerr := policy.ParseLenient(data)

		if lerr != nil {
			// Neither parser can read it. This IS the total-denial case, and
			// it is the only one that was ever true.
			return fmt.Errorf("INVALID — the daemon cannot parse this file either, so it is "+
				"denying ALL operations until it is fixed: %w", lerr)
		}
		if serr != nil {
			// The daemon runs this file. Saying otherwise sends the reader to
			// fix an outage that is not happening, and away from the rule that
			// actually stopped doing what they meant.
			fmt.Printf("⚠  NOT STRICTLY VALID — but the daemon DOES run this file: %v\n\n", serr)
			fmt.Println("   A rule the daemon cannot fully evaluate fails CLOSED: it still matches")
			fmt.Println("   `deny` and `ask`, and it can no longer satisfy an `allow`. The effect is")
			fmt.Println("   narrower access, not an outage — but a rule you meant to grant with may")
			fmt.Println("   have quietly stopped granting.")
			fmt.Printf("\n   The daemon reads it as %d rule(s), default %s.\n",
				len(lenient.Rules), lenient.Default)
			warnStaleHelperRule(lenient)
			warnAdvisoryAllowRules(lenient)
			warnUnreachableRules(lenient)
			warnUnaskableRules(lenient)
			warnDeprecatedSpellings(lenient)
			return nil
		}
		fmt.Printf("✓ valid — %d rule(s), default %s.\n", len(p.Rules), p.Default)
		warnStaleHelperRule(p)
		warnAdvisoryAllowRules(p)
		warnUnreachableRules(p)
		warnUnaskableRules(p)
		warnDeprecatedSpellings(p)
		return nil
	},
}

// warnAdvisoryAllowRules flags allow rules that grant on the strength of an
// identity the caller supplies.
//
// `agent:` and `tool:` come from the request body on /wrap, /store, /retrieve
// and /grant, so a rule granting access because of one is only as good as the
// caller's honesty — unless that caller presented an agent key. The daemon now
// refuses to satisfy an allow from an asserted identity, which means these
// rules quietly stop granting for keyless callers. Say so, because the failure
// looks like "my policy stopped working" rather than "my policy was never
// enforcing what I thought".
//
// Identities the DAEMON assigns (akasha-helper, akasha-list, …) are exempt:
// those endpoints ignore the body, so the name cannot be claimed.
func warnAdvisoryAllowRules(p *policy.Policy) {
	var flagged []int
	for i, r := range p.Rules {
		if r.Effect != policy.EffectAllow {
			continue
		}
		agentAsserted := r.Agent != "" && !strings.HasPrefix(strings.ToLower(r.Agent), "akasha-")
		toolAsserted := r.Tool != "" && !strings.HasPrefix(strings.ToLower(r.Tool), "akasha_")
		if agentAsserted || toolAsserted {
			flagged = append(flagged, i+1)
		}
	}
	if len(flagged) == 0 {
		return
	}
	fmt.Printf("\nℹ  rule(s) %v grant access based on `agent:` or `tool:`.\n\n", flagged)
	fmt.Print("   Those fields come from the request body, so they only grant to a caller that\n" +
		"   presented a valid agent key. A keyless caller claiming the same name is refused.\n" +
		"   If a rule stopped taking effect, the caller is probably missing its key:\n\n" +
		"     akasha status                 # shows agents whose key is missing or out of sync\n" +
		"     akasha agent resync <client>  # re-authorize an existing key\n\n" +
		"   To gate without depending on identity, match on server-derived fields instead\n" +
		"   (action, provider, instance, category, min_risk, sandbox, caller,\n    brokerable).\n\n")
}

// warnUnaskableRules flags `ask` rules on a machine that cannot prompt.
//
// "ask" fails closed, which is right, but it means a rule the user wrote as
// "pause and let me decide" behaves as "never" when there is no approval
// channel — headless box, no zenity installed, a systemd unit that never got
// DISPLAY. That is a policy quietly stricter than written, and the operator
// finds out mid-workflow from a denial that reads like a refusal. Say it here,
// where they are already looking at the file.
func warnUnaskableRules(p *policy.Policy) {
	n := 0
	for _, r := range p.Rules {
		if r.Effect == policy.EffectAsk {
			n++
		}
	}
	if n == 0 {
		return
	}
	why := policy.ApprovalChannel()
	if why == "" {
		return
	}
	fmt.Printf("\n⚠  %d `ask` rule(s), but this machine cannot prompt for approval:\n\n", n)
	fmt.Printf("     %s\n\n", why)
	fmt.Print("   Until that is fixed every one of them behaves as `deny`, which is safe\n" +
		"   but stricter than what the file says.\n\n")
}

// warnStaleHelperRule flags the pre-0.1.0-alpha.3 broker exception.
//
// Older starter policies permitted the credential broker with
// `action: retrieve` + `tool: akasha_helper` -> allow. "tool" is a request-body
// field, so that rule let ANY caller read raw plaintext by claiming the
// broker's name. The daemon now refuses the reserved akasha_* namespace in
// request bodies, so the rule can no longer be exploited — but it is dead
// weight that reads like a working permission, and someone will eventually
// copy it. Say so on every validate until it is gone.
func warnStaleHelperRule(p *policy.Policy) {
	for i, r := range p.Rules {
		if r.Action != "retrieve" || r.Effect != policy.EffectAllow {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(r.Tool), "akasha_") {
			continue
		}
		fmt.Printf("\n⚠  rule %d is obsolete and should be deleted:\n", i+1)
		fmt.Printf("     - {action: retrieve, tool: %s, effect: allow}\n\n", r.Tool)
		fmt.Print("   It was how the credential broker used to be permitted, but `tool` comes\n" +
			"   from the request body — so this rule let any caller read raw secrets by\n" +
			"   claiming the broker's name. The daemon now rejects that claim, and brokered\n" +
			"   use has its own action. Nothing needs to replace this rule: `broker` falls\n" +
			"   through to your default, or gate it explicitly, e.g.\n\n" +
			"     - {action: broker, provider: aws, instance: prod, effect: ask}\n\n")
		return
	}
}

// warnUnreachableRules reports rules a first-match evaluation can never reach.
//
// Nothing else catches this: Parse checks each rule in isolation, and every
// individual rule here is valid. The failure runs in the dangerous direction —
// a policy that reads like a lockdown, validates clean, and quietly does not
// apply the rule you wrote it for.
// warnDeprecatedSpellings names rules that still use a word this release
// accepts as an alias. Separate from the Lint report because these rules WORK;
// the only thing wrong with them is that they will stop parsing one release
// from now, and the fix is a rename, not a reorder.
func warnDeprecatedSpellings(p *policy.Policy) {
	ds := p.Deprecations()
	if len(ds) == 0 {
		return
	}
	fmt.Printf("\n⚠  %d rule(s) use a spelling that is going away:\n\n", len(ds))
	for _, s := range ds {
		fmt.Printf("     • %s\n", s)
	}
	fmt.Println()
}

func warnUnreachableRules(p *policy.Policy) {
	problems := p.Lint()
	if len(problems) == 0 {
		return
	}
	fmt.Printf("\n⚠  %d rule(s) will not do what they look like they do:\n\n", len(problems))
	for _, s := range problems {
		fmt.Printf("     • %s\n", s)
	}
	fmt.Print("\n   Rules are evaluated first-match, so a broader rule above a narrower one\n" +
		"   swallows it. Reorder so the specific cases come first.\n\n")
}

var policyDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Turn policy off deliberately (and stop the daemon denying everything)",
	Long: `Once a policy has been loaded, the daemon remembers it. If the file then
disappears it fails CLOSED and denies every gated operation, because it cannot
tell a deliberate removal from an attacker deleting the control.

This command is how you say the removal was deliberate: it forgets that a policy
was installed, so a missing policy.yaml goes back to meaning "not configured
yet" — allow everything.

To re-enable, write a policy file again (` + "`akasha policy init`" + `) — the next
operation picks it up, no restart needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		if err := vlt.ClearPolicyState(); err != nil {
			return err
		}
		path := policy.DefaultPath()
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Policy disabled — but %s still exists, so it will be picked up again\n", path)
			fmt.Println("on the next operation. Remove or rename it if you meant to stop enforcing.")
			return nil
		}
		fmt.Println("Policy disabled. All operations are allowed until a policy file exists again.")
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyInitCmd, policyValidateCmd, policyDisableCmd)
}

var policyPassphraseClear bool

// `akasha policy passphrase` sets the human-presence factor for `ask` rules.
//
// It is set here, from a terminal, and never over the socket. The whole point
// of the factor is that a process running as you cannot produce it; an endpoint
// that accepted one would be a way for exactly such a process to set its own.
var policyPassphraseCmd = &cobra.Command{
	Use:   "passphrase",
	Short: "Set the approval passphrase used by `ask_requires: passphrase`",
	Long: `Sets the passphrase an "ask" rule requires before it will allow an operation.

This is a HUMAN-PRESENCE factor, not a second encryption key. It unlocks
nothing: if it leaked, the holder could answer an approval prompt and nothing
else. It exists because a process running as you can read your files and
impersonate your agents — but it cannot produce a passphrase you only ever
typed.

Add to ~/.akasha/policy.yaml to require it:

  ask_requires: passphrase

Rules with "effect: ask" then prompt for it instead of showing a button.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vlt, err := vault.Open(dbPath, vault.Options{})
		if err != nil {
			return err
		}
		defer vlt.Close()

		if policyPassphraseClear {
			if err := vlt.ClearApprovalPassphrase(); err != nil {
				return err
			}
			fmt.Println("✓ Approval passphrase cleared.")
			fmt.Println("  Any `ask_requires: passphrase` rule now DENIES rather than falling back")
			fmt.Println("  to a button — a factor that cannot be checked has not been satisfied.")
			return nil
		}

		fmt.Print("New approval passphrase: ")
		first, err := readPassphrase()
		if err != nil {
			return err
		}
		fmt.Print("\nConfirm: ")
		second, err := readPassphrase()
		fmt.Println()
		if err != nil {
			return err
		}
		if string(first) != string(second) {
			return fmt.Errorf("the two entries did not match; nothing was changed")
		}
		if len(first) == 0 {
			return fmt.Errorf("an empty passphrase would be a factor anything can produce; nothing was changed")
		}
		if err := vlt.SetApprovalPassphrase(first); err != nil {
			return err
		}
		fmt.Println("✓ Approval passphrase set.")
		fmt.Println("  It is stored only as an Argon2id verifier — it cannot be read back,")
		fmt.Println("  and it decrypts nothing.")
		fmt.Println("  Require it by adding `ask_requires: passphrase` to your policy.")
		return nil
	},
}
