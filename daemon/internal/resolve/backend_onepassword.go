package resolve

import (
	"fmt"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// onepassword-cli resolves a single secret reference via the 1Password CLI:
//
//   op read --no-newline -- <ref>      # ref e.g. "op://Vault/item/field"
//
// The reference is the only template-supplied value and is passed as one argv
// element after "--", so it cannot inject flags or a command. Auth is a
// service-account token (OP_SERVICE_ACCOUNT_TOKEN) or a Connect host/token,
// passed through the scrubbed env — nothing else reaches the subprocess.
//
// `op read` returns one field's value, so the spec's map must bind exactly one
// output ("value") to a credential field.
func init() {
	register(&backend{
		name:       "onepassword-cli",
		defaultBin: "op",
		binEnv:     "AKASHA_OP_BIN",
		allowEnv:   []string{"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "HOME"},
		buildArgs: func(ref string, s template.SourceSpec) ([]string, error) {
			if len(s.Map) != 1 {
				return nil, fmt.Errorf("onepassword-cli resolves one value (op read) — map must bind exactly one output")
			}
			return []string{"read", "--no-newline", "--", ref}, nil
		},
		parse: func(stdout []byte, s template.SourceSpec) (map[string]string, error) {
			val := strings.TrimRight(string(stdout), "\r\n")
			if val == "" {
				return nil, fmt.Errorf("onepassword-cli returned an empty value")
			}
			out := make(map[string]string, 1)
			for _, field := range s.Map { // exactly one, enforced in buildArgs
				out[field] = val
			}
			return out, nil
		},
	})
}
