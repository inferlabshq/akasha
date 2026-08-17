package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/daemon/internal/resolve"
	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
)

// The `template` command group is the authoring loop for community plugins.
// Akasha's value is the format, not a pile of built-in providers: anyone can
// drop a YAML into ~/.akasha/templates/ and integrate a new login without a
// daemon change or a PR. These commands let an author write one, prove it
// parses, and — crucially — see exactly what it would DO before trusting it:
//
//   akasha template validate ./vercel.yaml   # does it parse + satisfy the schema?
//   akasha template explain  ./vercel.yaml   # capability manifest + dry-run preview
//   akasha template list                     # everything loaded (shipped + user)
//   akasha template new vercel > vercel.yaml # scaffold a skeleton to edit

var templateCmd = &cobra.Command{
	Use:     "template",
	Aliases: []string{"templates", "tpl"},
	Short:   "Author, validate, and inspect provider plugins",
	Long: `Provider plugins are pure-data YAML files describing how a login's
credentials are shaped, discovered, delivered, and owned. No providers are
compiled in: a curated bundle ships as data in ` + template.ShippedDir() + `,
and your own plugins (which can override shipped ones) live in ` + template.UserDir() + `.

The format is documented in docs/PLUGIN_FORMAT.md. These commands are the
authoring loop: write a plugin, validate it, and preview what it would do.`,
}

var templateValidateCmd = &cobra.Command{
	Use:           "validate <file>",
	Short:         "Parse and schema-check a plugin file",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: false,
	RunE: func(cmd *cobra.Command, args []string) error {
		tpl, err := parseTemplateFile(args[0])
		if err != nil {
			// A schema error is the expected, useful output here. Returning it
			// lets cobra print it and exit non-zero so CI / editors can gate.
			return fmt.Errorf("invalid: %w", err)
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "✓ valid — %s %q (version %d)\n", tpl.Kind, tpl.Name, tpl.Version)
		fmt.Fprintf(w, "  capabilities: %s\n", tpl.Capabilities())
		if existing := template.Get(tpl.Name); existing != nil && existing.Origin() != "" {
			fmt.Fprintf(w, "  note: name %q is already provided by %s — dropping yours in %s would override it.\n",
				tpl.Name, existing.Origin(), template.UserDir())
		}
		return nil
	},
}

var templateExplainCmd = &cobra.Command{
	Use:   "explain <file|name>",
	Short: "Show what a plugin can do, and dry-run what it would write/run",
	Long: `Prints a capability manifest (what the plugin reads, writes, owns, and
runs) followed by a dry-run preview rendered with placeholder secrets — no real
credentials are read and nothing is written. Use it to audit a third-party
plugin before trusting it, or to debug your own.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		tpl, err := loadTemplateArg(args[0])
		if err != nil {
			return err
		}
		explainTemplate(cmd.OutOrStdout(), tpl)
		return nil
	},
}

var templateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all loaded plugins (built-in and user) with capabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		all := template.All()
		skips := template.Skipped()
		if len(all) == 0 && len(skips) == 0 {
			fmt.Fprintln(w, "No templates loaded.")
			return nil
		}
		fmt.Fprintf(w, "Search path: %s\n", strings.Join(template.Dirs(), string(os.PathListSeparator)))
		fmt.Fprintf(w, "User plugin dir (overrides): %s\n\n", template.UserDir())
		store, _ := trust.Load() // nil-safe in trustStatus
		for _, t := range all {
			fmt.Fprintf(w, "  %-14s %-10s %-12s %s\n", t.Name, "["+originLabel(t)+"]", trustStatus(store, t), t.Capabilities())
		}

		// Capabilities this daemon is too old to implement. The template still
		// works — this is what it lost, named, so nobody has to discover it by
		// hitting a failure somewhere else later.
		if degraded := template.Degradations(); len(degraded) > 0 {
			fmt.Fprintf(w, "\nDegraded (%d capability/ies dropped; these templates still work):\n", len(degraded))
			for _, d := range degraded {
				fmt.Fprintf(w, "  %s\n    %s\n", d.Path, d.Degradation)
			}
		}

		// A provider that fails to parse is simply absent from the list above,
		// and the first symptom is `assume` failing for a provider the user can
		// see on disk. Naming the file and the reason here turns that into a
		// one-line diagnosis — most often a template written for a newer daemon
		// than the one running.
		if len(skips) > 0 {
			fmt.Fprintf(w, "\nNot loaded (%d):\n", len(skips))
			for _, s := range skips {
				fmt.Fprintf(w, "  %s\n    %s\n", s.Path, s.Reason)
			}
			fmt.Fprintln(w, "\nA template that names a primitive this daemon does not know fails to load.\nIf these came with a newer release, upgrade the daemon: they version together.")
		}
		return nil
	},
}

var templateNewCmd = &cobra.Command{
	Use:   "new <name>",
	Short: "Print a starter plugin skeleton to stdout",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		fmt.Fprintf(cmd.OutOrStdout(), templateSkeleton, name, name)
		return nil
	},
}

var templateTrustYes bool

var templateTrustCmd = &cobra.Command{
	Use:   "trust <name>",
	Short: "Approve a plugin's high-trust effects (e.g. owning agent-session env)",
	Long: `Records approval for a loaded plugin's sensitive capabilities, bound to
the file's SHA-256. Until approved, akasha will not apply those effects (for
example, 'akasha setup' will not let the plugin own an agent session's env).
Editing the file after approval revokes it until you re-approve.

Review first with 'akasha template explain <name>'.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		tpl := template.Get(args[0])
		if tpl == nil {
			return fmt.Errorf("no loaded template named %q (see `akasha template list`)", args[0])
		}
		w := cmd.OutOrStdout()
		caps := tpl.SensitiveCapabilities()
		if len(caps) == 0 {
			fmt.Fprintf(w, "%q has no high-trust capabilities — nothing to approve.\n", tpl.Name)
			return nil
		}
		sum, err := template2SHA(tpl)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Plugin:       %s\n", tpl.Name)
		fmt.Fprintf(w, "Source:       %s\n", tpl.Origin())
		fmt.Fprintf(w, "SHA-256:      %s\n", sum)
		fmt.Fprintf(w, "Will approve: %s\n", strings.Join(caps, ", "))
		fmt.Fprintln(w, "(run `akasha template explain "+tpl.Name+"` to see exactly what it does)")
		if !templateTrustYes {
			fmt.Fprint(w, "Approve? [y/N] ")
			if !readYes(cmd.InOrStdin()) {
				fmt.Fprintln(w, "Not approved.")
				return nil
			}
		}
		store, err := trust.Load()
		if err != nil {
			return err
		}
		if err := store.Approve(tpl); err != nil {
			return err
		}
		if err := store.Save(); err != nil {
			return err
		}
		fmt.Fprintf(w, "✓ Approved %q for: %s\n", tpl.Name, strings.Join(caps, ", "))
		return nil
	},
}

var templateUntrustCmd = &cobra.Command{
	Use:          "untrust <name>",
	Short:        "Revoke a plugin's approval",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := trust.Load()
		if err != nil {
			return err
		}
		if !store.Revoke(args[0]) {
			fmt.Fprintf(cmd.OutOrStdout(), "%q was not approved — nothing to revoke.\n", args[0])
			return nil
		}
		if err := store.Save(); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Revoked approval for %q.\n", args[0])
		return nil
	},
}

var templateResolveInstance string

var templateResolveCmd = &cobra.Command{
	Use:          "resolve <name>",
	Short:        "Resolve a plugin's credential from its source backend (trust-gated)",
	Long:         "Runs the plugin's source backend (e.g. 1Password) to fetch the credential for an instance. Refused unless the plugin is trusted. Never prints secret values — only confirms which fields resolved.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		tpl := template.Get(args[0])
		if tpl == nil {
			return fmt.Errorf("no loaded template named %q (see `akasha template list`)", args[0])
		}
		if len(tpl.Source) == 0 {
			return fmt.Errorf("%q has no source backend to resolve", tpl.Name)
		}
		store, err := trust.Load()
		if err != nil {
			return err
		}
		fields, err := resolve.ResolveTemplate(cmd.Context(), store, tpl, 0, templateResolveInstance)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(fields))
		for f, v := range fields {
			names = append(names, fmt.Sprintf("%s (%d chars)", f, len(v))) // never the value
		}
		sort.Strings(names)
		fmt.Fprintf(cmd.OutOrStdout(), "✓ resolved %d field(s) from %s: %s\n", len(fields), tpl.Source[0].Backend, strings.Join(names, ", "))
		return nil
	},
}

func init() {
	templateTrustCmd.Flags().BoolVarP(&templateTrustYes, "yes", "y", false, "Approve without the interactive prompt")
	templateResolveCmd.Flags().StringVar(&templateResolveInstance, "instance", "default", "Instance to resolve (e.g. a profile or account name)")
	templateCmd.AddCommand(templateValidateCmd, templateExplainCmd, templateListCmd, templateNewCmd, templateTrustCmd, templateUntrustCmd, templateResolveCmd)
}

// template2SHA returns the digest Store.Approve will record: the hash of the
// bytes this template was PARSED from, not of the file as it stands now. Those
// two diverge whenever the file changes between load and prompt, and showing
// the reviewer a hash the daemon is not about to record is how a human approves
// one thing while the store binds another.
func template2SHA(tpl *template.Template) (string, error) {
	if tpl.Origin() == "" || tpl.Digest() == "" {
		return "", fmt.Errorf("template %q was not loaded from a file, so there are no bytes to bind an approval to — install it under ~/.akasha/templates and reload the daemon", tpl.Name)
	}
	return tpl.Digest(), nil
}

// readYes reads one line and reports whether it is an affirmative (y/yes).
func readYes(r io.Reader) bool {
	var s string
	fmt.Fscanln(r, &s)
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes"
}

// trustStatus labels a template's trust state for `list`.
func trustStatus(store *trust.Store, t *template.Template) string {
	if len(t.SensitiveCapabilities()) == 0 {
		return "—"
	}
	if store != nil {
		if ok, _ := store.Approved(t); ok {
			return "trusted"
		}
	}
	return "NEEDS TRUST"
}

// parseTemplateFile reads and parses a plugin file (the author's work in
// progress), independent of the loaded registry.
func parseTemplateFile(path string) (*template.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return template.Parse(data)
}

// loadTemplateArg resolves an explain/validate argument that may be either a
// path to a file on disk or the name of an already-loaded template.
func loadTemplateArg(arg string) (*template.Template, error) {
	if _, statErr := os.Stat(arg); statErr == nil {
		return parseTemplateFile(arg)
	}
	if t := template.Get(arg); t != nil {
		return t, nil
	}
	return nil, fmt.Errorf("no file or loaded template named %q", arg)
}

// explainTemplate prints the capability manifest and dry-run preview. The
// manifest is the same surface a future trust gate will gate on: what does
// this plugin READ, WRITE into agent sessions, and RUN.
func explainTemplate(w io.Writer, tpl *template.Template) {
	out := func(format string, a ...interface{}) { fmt.Fprintf(w, format, a...) }
	out("%s %q (version %d)\n", tpl.Kind, tpl.Name, tpl.Version)
	out("capabilities: %s\n\n", tpl.Capabilities())

	// ── Capability manifest ───────────────────────────────────────────────
	out("CAPABILITIES\n")
	if len(tpl.Discover) > 0 {
		out("  reads:\n")
		for _, d := range tpl.Discover {
			out("    - %s (%s)\n", d.Path, d.Source)
		}
	}
	for _, s := range tpl.Source {
		mode := s.Mode
		if mode == "" {
			mode = "on-demand"
		}
		out("  runs backend: %s (%s) ref %q\n", s.Backend, mode, s.Ref)
	}
	if tpl.Agent != nil {
		var owns []string
		for _, d := range tpl.Agent.Own {
			owns = append(owns, d.Env)
		}
		sort.Strings(owns)
		out("  owns agent session env: %s\n", strings.Join(owns, ", "))
	}
	runs := deliverModes(tpl)
	if len(runs) > 0 {
		out("  delivers via: %s\n", strings.Join(runs, ", "))
	}
	// Spell out exactly which facts this provider discloses. The contract may
	// compute more; the reader of a template should be able to see the limit
	// without going and reading the daemon's contract registry.
	if degraded := template.DegradationsFor(tpl.Origin()); len(degraded) > 0 {
		out("  DROPPED by this daemon (declared, but not implemented here):\n")
		for _, d := range degraded {
			out("    %s\n", d.Degradation)
		}
	}
	if d := tpl.DescribeDeliver(); d != nil {
		revealed := make([]string, 0, len(d.Map))
		for name := range d.Map {
			revealed = append(revealed, name)
		}
		sort.Strings(revealed)
		out("  describes via %s, revealing only: %s\n", d.Contract, strings.Join(revealed, ", "))
	}
	out("\n")

	// ── Dry-run preview, rendered with placeholder secrets ────────────────
	creds := placeholderCreds(tpl)
	out("DRY RUN (placeholder secrets; nothing is read or written)\n")

	if d := firstDeliver(tpl, "file"); d != nil {
		if r, err := tpl.Render("default", creds); err == nil {
			out("  file %q would contain:\n", r.FileName)
			indent(w, string(r.Body), "    | ")
			if len(r.Env) > 0 {
				out("  and set env: %s\n", kvLine(r.Env))
			}
		}
	}
	if d := firstDeliver(tpl, "env"); d != nil && firstDeliver(tpl, "file") == nil {
		if r, err := tpl.Render("default", creds); err == nil {
			out("  would set env: %s\n", kvLine(r.Env))
		}
	}
	if d := firstDeliver(tpl, "helper"); d != nil {
		if b, err := template.ExecuteHelper(tpl, creds, 900); err == nil {
			out("  helper (%s) would emit on each call:\n", d.Format)
			indent(w, string(b), "    | ")
		}
	}

	// Ownership wiring is the highest-trust effect — show exactly what lands in
	// the agent's session for one sample instance. The command is always the
	// akasha helper (Go-rendered); there is no template-supplied command.
	if tpl.Agent != nil {
		out("  on `akasha setup`, agent sessions would gain (sample instance \"default\"):\n")
		for _, d := range tpl.Agent.Own {
			out("    env %s = <agent_dir>/%s\n", d.Env, d.File)
			switch d.Mechanism {
			case template.MechCredentialProcess:
				section := strings.ReplaceAll(d.Section, "{instance}", "default")
				out("      [%s] credential_process = akasha helper %s --instance default\n", section, tpl.Name)
			case template.MechGitCredentialHelper:
				if d.Inherit {
					out("      [include] path = ~/.gitconfig\n")
				}
				out("      [credential \"https://%s\"] helper = !akasha helper %s --instance default\n", d.Host, tpl.Name)
			case template.MechDecoy:
				out("      (empty decoy file — blanks the tool's default credential path)\n")
			}
		}
	}
}

// placeholderCreds builds a credential map with a visible placeholder for every
// declared field, so render/helper previews never need a real secret.
func placeholderCreds(tpl *template.Template) map[string]string {
	creds := map[string]string{}
	for f := range tpl.Credential.Fields {
		creds[f] = "<" + f + ">"
	}
	return creds
}

// originLabel classifies where a loaded template came from, for `list`.
func originLabel(t *template.Template) string {
	dir := filepath.Dir(t.Origin())
	switch dir {
	case template.ShippedDir():
		return "shipped"
	case template.UserDir():
		return "user"
	case ".":
		return "?"
	default:
		return dir
	}
}

func deliverModes(tpl *template.Template) []string {
	var modes []string
	for _, d := range tpl.Deliver {
		modes = append(modes, d.Mode)
	}
	return modes
}

func firstDeliver(tpl *template.Template, mode string) *template.DeliverMode {
	for i := range tpl.Deliver {
		if tpl.Deliver[i].Mode == mode {
			return &tpl.Deliver[i]
		}
	}
	return nil
}

func kvLine(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, " ")
}

func indent(w io.Writer, body, prefix string) {
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		fmt.Fprintf(w, "%s%s\n", prefix, line)
	}
}

const templateSkeleton = `# %s provider plugin — see docs/PLUGIN_FORMAT.md
kind: provider
name: %s
version: 1

# What a credential of this provider IS.
credential:
  fields:
    token: {secret: true}

# How the secret is handed to a consumer (best-first). 'helper' is the gold
# tier: per-use, audited, never at rest. 'env' is the simplest.
deliver:
  - mode: env
    env:
      EXAMPLE_TOKEN: "{token}"

# Optional: where existing credentials already live, so 'akasha discover' can
# vault them.
# discover:
#   - source: env-lines
#     path: ~/.config/example/token
#     instances: single
#     map: {token: value}
`
