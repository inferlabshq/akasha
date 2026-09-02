package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// assertAssumable refuses a --assume label the vault does not actually hold.
//
// Both run and exec checked the PROVIDER and never the label, so a profile that
// does not exist was accepted and reported as granted. Measured, on a vault
// holding exactly three labels and no github entry at all:
//
//	akasha exec --assume github:this-profile-does-not-exist -- …   -> ran, exit 0
//	akasha run claude --assume github:work -- …
//	    akasha run: agent run:claude · may broker: github:work · sandbox: on
//
// The banner is the problem. It states a capability the run does not have, so
// the agent is launched believing a credential is available, and the failure —
// if it comes at all — arrives later and names something else. An unknown
// PROVIDER was already refused immediately; an unknown profile under a known
// provider was not.
//
// Unverifiable is not the same as absent. If the label list cannot be fetched
// the check is SKIPPED rather than failed: the daemon being unreachable is its
// own error with its own message, and turning it into "no such credential"
// would be this same bug pointed the other way.
func assertAssumable(labels []string) error {
	if len(labels) == 0 {
		return nil
	}
	known, err := knownLabels()
	if err != nil || known == nil {
		return nil // cannot verify; the real failure will speak for itself
	}
	for _, want := range labels {
		if known[want] {
			continue
		}
		have := make([]string, 0, len(known))
		for k := range known {
			have = append(have, k)
		}
		sort.Strings(have)
		if len(have) == 0 {
			return fmt.Errorf("this vault holds no credentials, so %q cannot be brokered.\n"+
				"  Vault one first:  akasha discover all   or   akasha put %s", want, want)
		}
		return fmt.Errorf("no credential named %q in this vault.\n"+
			"  This vault has: %s\n"+
			"  Vault it first with `akasha put %s`, or use one of the names above.",
			want, strings.Join(have, ", "), want)
	}
	return nil
}

// knownLabels asks the daemon what the vault actually holds.
func knownLabels() (map[string]bool, error) {
	resp, err := daemonGet(socketPath, "/label/list?prefix=")
	if err != nil {
		return nil, err
	}
	// A bare JSON array, not an object with a "labels" key. Unmarshalling into
	// the wrong shape fails silently here and the caller then SKIPS the check,
	// so getting this wrong turns the guard into a no-op that still compiles.
	var names []string
	if err := json.Unmarshal([]byte(resp), &names); err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(names))
	for _, l := range names {
		known[l] = true
	}
	return known, nil
}
