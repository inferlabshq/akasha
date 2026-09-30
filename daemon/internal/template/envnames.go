package template

import "sort"

// CredentialEnvNames returns every environment variable name the loaded
// templates say can carry a credential: the keys a `source: env` or
// `source: env-lines` discover block maps, and the variables a `mode: env`
// deliver block would set.
//
// This is the environment counterpart of the file list the sandbox masks.
// A supervised run points the AWS CLI at a generated config whose
// credential_process brokers per operation — but the CLI's own lookup order
// puts static environment variables FIRST, so an AWS_ACCESS_KEY_ID exported in
// the launching shell would win over the broker, never be audited, and sit in
// the child's environment for any process inside to read. The run therefore
// removes these names from what the child inherits, and says which.
//
// Derived from the templates rather than kept by hand, for the same reason
// the file masks are: a provider's discover block is already the list of where
// its credential lives, and a new template is covered the day it lands.
func CredentialEnvNames() []string {
	seen := map[string]bool{}
	for _, t := range All() {
		for _, d := range t.Discover {
			if d.Source != "env" && d.Source != "env-lines" {
				continue
			}
			for _, name := range d.Map {
				if name != "" {
					seen[name] = true
				}
			}
		}
		for _, m := range t.Deliver {
			if m.Mode != "env" {
				continue
			}
			for name := range m.Env {
				if name != "" {
					seen[name] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
