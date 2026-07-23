package assume

import (
	"time"

	"github.com/inferlabshq/akasha/internal/template"
)

// writerFor resolves the writer for a provider at call time (not at init), so
// it always reflects the currently-loaded template registry — there are no
// compiled-in providers, and the template search path may be configured after
// this package initializes. A provider template that declares a file or env
// deliver mode wins; otherwise a hand-written Go writer (today only "env", the
// universal fallback) is used. That ordering is the porting mechanism: a
// template overrides a Go writer of the same name.
func writerFor(provider string) (writer, bool) {
	if t := template.Get(provider); t != nil && (t.FileDeliver() != nil || t.EnvDeliver() != nil) {
		return templateWriter(t), true
	}
	if w, ok := providers[provider]; ok {
		return w, true
	}
	return nil, false
}

// templateProviderNames lists provider templates that can be assumed (declare a
// file or env deliver mode).
func templateProviderNames() []string {
	var out []string
	for _, t := range template.Providers() {
		if t.FileDeliver() != nil || t.EnvDeliver() != nil {
			out = append(out, t.Name)
		}
	}
	return out
}

// templateWriter adapts a provider template to the assume writer interface.
func templateWriter(t *template.Template) writer {
	return func(dir, profile string, creds map[string]string, expires time.Time) (*Result, error) {
		r, err := t.Render(profile, creds)
		if err != nil {
			return nil, err
		}
		res := &Result{Provider: t.Name, Profile: profile, ExpiresAt: expires}
		if r.FileName != "" {
			path, err := writeSessionFile(dir, r.FileName, r.Body, expires)
			if err != nil {
				return nil, err
			}
			if err := r.ResolveEnv(path); err != nil {
				return nil, err
			}
			res.Path = path
		}
		res.Env = r.Env
		return res, nil
	}
}
