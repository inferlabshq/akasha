package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// scrubCredentialEnv removes from env every variable whose name is in names,
// and reports which names were present. Matching is exact and case-sensitive,
// as the tools that read these variables match them.
//
// Called on the INHERITED environment, before anything the run or exec wires
// in is applied, so a value akasha itself delivers (an `env:` provider's
// materialized variable) is never touched — the scrub is of what came in from
// the launching shell, not of what akasha decided to hand out.
func scrubCredentialEnv(env []string, names []string) (kept []string, removed []string) {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	kept = env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if drop[name] {
			removed = append(removed, name)
			continue
		}
		kept = append(kept, kv)
	}
	sort.Strings(removed)
	return kept, removed
}

// scrubInheritedCredentials is scrubCredentialEnv against the names the
// templates declare, with the operator-facing line that says what happened.
//
// It prints rather than refusing: the variable being set is ordinary — a shell
// profile exports it, a CI image bakes it in — and the person launching the run
// did not ask for it to be handed to the agent. Removing it is what makes the
// broker the path actually taken; naming it is what keeps that from being a
// silent change to their environment.
func scrubInheritedCredentials(env []string, verb string, w io.Writer) []string {
	kept, removed := scrubCredentialEnv(env, template.CredentialEnvNames())
	if len(removed) > 0 {
		fmt.Fprintf(w, "akasha %s: removed from the environment: %s — plaintext credentials the "+
			"launching shell exported. Inside, the tools reach these through the broker instead; "+
			"the shell's copies would have taken precedence, unaudited.\n", verb, strings.Join(removed, ", "))
	}
	return kept
}
