package assume

import (
	"fmt"
	"time"
)

// writeEnv is the universal fallback provider for secrets that don't have a
// native file format (Stripe keys, database URLs, custom API tokens, …). The
// credential map's field names ARE the environment variable names, so a secret
// stored as {"STRIPE_API_KEY": "sk_live_…"} assumes straight into
// STRIPE_API_KEY. No file is written — the values go directly into the env the
// caller sets.
//
// Store with:  akasha put env:stripe STRIPE_API_KEY
// Use with:    akasha exec --assume env:stripe -- ./charge.sh
func writeEnv(_ string, profile string, creds map[string]string, expires time.Time) (*Result, error) {
	if len(creds) == 0 {
		return nil, fmt.Errorf("env assume: no fields to export")
	}
	env := make(map[string]string, len(creds))
	for k, v := range creds {
		env[k] = v
	}
	return &Result{
		Provider:  "env",
		Profile:   profile,
		Env:       env,
		ExpiresAt: expires,
	}, nil
}
