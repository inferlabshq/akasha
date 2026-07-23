package template

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// placeholder matches {name} where name is a lowercase identifier. This is
// the entire template language: no logic, no nesting, no escapes. A literal
// brace sequence that happens to match would be rejected at load by
// checkVars, so it cannot silently pass through.
var placeholder = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// Subst replaces every {name} placeholder from vars. Unknown placeholders
// are an error — templates are validated at load time, so hitting one here
// means the caller built the wrong context, and failing loudly beats
// emitting a credential file with a literal "{secret_access_key}" in it.
func Subst(s string, vars map[string]string) (string, error) {
	var errs []string
	out := placeholder.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := vars[name]
		if !ok {
			errs = append(errs, name)
			return m
		}
		return v
	})
	if len(errs) > 0 {
		return "", fmt.Errorf("unknown placeholder(s): %s", strings.Join(errs, ", "))
	}
	return out, nil
}

// checkVars verifies at load time that every placeholder in s is in allowed.
func checkVars(s string, allowed map[string]bool) error {
	var bad []string
	for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
		if !allowed[m[1]] {
			bad = append(bad, m[1])
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		var ok []string
		for v := range allowed {
			ok = append(ok, v)
		}
		sort.Strings(ok)
		return fmt.Errorf("placeholder(s) %s not allowed here (allowed: %s)",
			strings.Join(bad, ", "), strings.Join(ok, ", "))
	}
	return nil
}

// Rendered is the materialized output of a deliver mode, before any file is
// written: the caller (the assume package, later the helper command) decides
// where bytes land and then resolves the {path} placeholder in Env.
type Rendered struct {
	FileName string            // empty for env-only modes
	Body     []byte            // file content (nil for env-only)
	Env      map[string]string // values may contain {path} until ResolveEnv
	envRaw   map[string]string
	Expires  time.Time
}

// ResolveEnv fills the {path} placeholder once the caller knows where the
// file was written.
func (r *Rendered) ResolveEnv(path string) error {
	env := make(map[string]string, len(r.envRaw))
	for k, v := range r.envRaw {
		resolved, err := Subst(v, map[string]string{"path": path})
		if err != nil {
			return fmt.Errorf("env %s: %w", k, err)
		}
		env[k] = resolved
	}
	r.Env = env
	return nil
}

// Render materializes the template's best non-interactive deliver mode
// (file if declared, else env) for one instance. It enforces the credential
// schema: every non-optional field must be present, and only declared fields
// substitute. Conditional render lines (if_set) are emitted only when their
// optional field has a value.
func (t *Template) Render(instance string, creds map[string]string) (*Rendered, error) {
	// Normalize first: aliases resolve, undeclared keys drop, required fields
	// are enforced. Everything below sees only declared field names.
	resolved, err := t.ResolveCreds(creds)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{"instance": instance}
	for f, v := range resolved {
		vars[f] = v
	}

	// unset: declared optional fields with no value. Render lines guarded by
	// if_set skip them; env entries that reference one are dropped entirely
	// (e.g. AWS_SESSION_TOKEN when there is no session token).
	unset := map[string]bool{}
	for f, spec := range t.Credential.Fields {
		if spec.Optional && resolved[f] == "" {
			unset[f] = true
		}
	}

	if d := t.FileDeliver(); d != nil {
		name, err := Subst(d.Name, map[string]string{"instance": instance})
		if err != nil {
			return nil, fmt.Errorf("%s file name: %w", t.Name, err)
		}
		var b strings.Builder
		for _, l := range d.Render {
			if l.IfSet != "" && resolved[l.IfSet] == "" {
				continue
			}
			line, err := Subst(l.Line, vars)
			if err != nil {
				return nil, fmt.Errorf("%s render: %w", t.Name, err)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		return &Rendered{FileName: name, Body: []byte(b.String()), envRaw: envWithVars(d.Env, vars, unset)}, nil
	}

	if d := t.EnvDeliver(); d != nil {
		r := &Rendered{envRaw: envWithVars(d.Env, vars, unset)}
		if err := r.ResolveEnv(""); err != nil {
			return nil, err
		}
		return r, nil
	}
	return nil, fmt.Errorf("%s: no file or env deliver mode declared", t.Name)
}

// envWithVars pre-substitutes everything except {path}, which only exists
// after the file is written. Entries referencing an unset optional field are
// dropped rather than emitted with an empty value.
func envWithVars(env, vars map[string]string, unset map[string]bool) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		skip := false
		for _, m := range placeholder.FindAllStringSubmatch(v, -1) {
			if unset[m[1]] {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		resolved := placeholder.ReplaceAllStringFunc(v, func(m string) string {
			name := m[1 : len(m)-1]
			if name == "path" {
				return m // resolved later by ResolveEnv
			}
			if val, ok := vars[name]; ok {
				return val
			}
			return m
		})
		out[k] = resolved
	}
	return out
}
