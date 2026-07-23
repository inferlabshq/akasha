// Package resolve executes a template's source backends to fetch a credential
// from an external secrets manager. It is the "code" half of the plugin format,
// so it is deliberately constrained per docs/PLUGIN_FORMAT.md §7:
//
//   - No commands in data. A template selects a NAMED backend; the backend's
//     binary and argv are built here in Go from typed params — never a command
//     string from the YAML.
//   - No shell. Execution is exec.CommandContext(bin, args...); a poisoned param
//     is one literal argv element, not a command. A "--" guard blocks flag
//     injection.
//   - Allowlisted binary. The binary is the backend's fixed name, overridable
//     only by an explicit operator env var (AKASHA_<BACKEND>_BIN) — never by the
//     template.
//   - Scrubbed env. The subprocess gets only the backend's declared env
//     allowlist — never the daemon's env, other secrets, or AKASHA_* keys.
//   - Bounded. Context timeout and a stdout size cap.
//   - Trust-gated. ResolveTemplate refuses unless the template is approved
//     (signature or explicit trust) — running a backend is CapRunBackend.
package resolve

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/template"
	"github.com/inferlabshq/akasha/daemon/internal/trust"
)

const (
	defaultTimeout = 20 * time.Second
	maxStdout      = 1 << 20 // 1 MiB
	maxStderr      = 8 << 10
)

// backend is a Go-owned resolver primitive. The template never supplies any of
// this — only the params that buildArgs consumes.
type backend struct {
	name       string
	defaultBin string                                                // allowlisted binary
	binEnv     string                                                // operator override env var (absolute path)
	allowEnv   []string                                              // env vars passed through to the subprocess
	buildArgs  func(ref string, s template.SourceSpec) ([]string, error)
	parse      func(stdout []byte, s template.SourceSpec) (map[string]string, error)
}

var backends = map[string]*backend{}

func register(b *backend) { backends[b.name] = b }

// ResolveTemplate resolves source[idx] of a template for an instance, after
// confirming the template is trusted. This is the gated entry point.
func ResolveTemplate(ctx context.Context, store *trust.Store, tpl *template.Template, idx int, instance string) (map[string]string, error) {
	if idx < 0 || idx >= len(tpl.Source) {
		return nil, fmt.Errorf("source index %d out of range", idx)
	}
	ok, err := store.Approved(tpl)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("template %q is not trusted to run a backend — approve it (`akasha template trust %s`) or trust its publisher", tpl.Name, tpl.Name)
	}
	return resolveSpec(ctx, tpl.Source[idx], instance)
}

// resolveSpec runs one backend for one instance. It performs no trust check —
// callers use ResolveTemplate.
func resolveSpec(ctx context.Context, s template.SourceSpec, instance string) (map[string]string, error) {
	b := backends[s.Backend]
	if b == nil {
		return nil, fmt.Errorf("backend %q is declared but not implemented in this build", s.Backend)
	}
	ref, err := template.Subst(s.Ref, substVars(s, instance))
	if err != nil {
		return nil, fmt.Errorf("%s ref: %w", s.Backend, err)
	}
	bin, err := b.binary()
	if err != nil {
		return nil, err
	}
	args, err := b.buildArgs(ref, s)
	if err != nil {
		return nil, err
	}

	cctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...) // no shell
	cmd.Env = b.scrubbedEnv()
	var out, errb bytes.Buffer
	cmd.Stdout = &capWriter{w: &out, max: maxStdout}
	cmd.Stderr = &capWriter{w: &errb, max: maxStderr}

	if err := cmd.Run(); err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("%s backend timed out after %s", s.Backend, defaultTimeout)
		}
		return nil, fmt.Errorf("%s backend failed: %v: %s", s.Backend, err, oneLine(errb.String()))
	}
	return b.parse(out.Bytes(), s)
}

// binary resolves the backend's executable: an operator-set absolute path wins;
// otherwise the fixed name is looked up on PATH. The template can never choose.
// Either way the resolved binary (and its directory) must not be world-writable
// — that is the PATH-hijack vector (an attacker who can write into a directory
// on the daemon's PATH plants a malicious `op`). Operators can pin an absolute
// path with AKASHA_<BACKEND>_BIN to bypass PATH entirely.
func (b *backend) binary() (string, error) {
	if p := os.Getenv(b.binEnv); p != "" {
		if !filepath.IsAbs(p) {
			return "", fmt.Errorf("%s must be an absolute path", b.binEnv)
		}
		if err := safeExecutable(p); err != nil {
			return "", fmt.Errorf("%s=%s: %w", b.binEnv, p, err)
		}
		return p, nil
	}
	path, err := exec.LookPath(b.defaultBin)
	if err != nil {
		return "", fmt.Errorf("%s backend needs %q on PATH (or set %s); not found", b.name, b.defaultBin, b.binEnv)
	}
	if err := safeExecutable(path); err != nil {
		return "", fmt.Errorf("%s resolved to an unsafe %q (%w); pin a trusted path with %s", b.name, path, err, b.binEnv)
	}
	return path, nil
}

// safeExecutable rejects a binary, or its containing directory, that is
// world-writable — anyone could replace it. Group-writable is allowed
// (e.g. Homebrew's admin-group dirs), so legitimate installs aren't flagged.
func safeExecutable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("not a regular file")
	}
	if fi.Mode()&0o002 != 0 {
		return fmt.Errorf("binary is world-writable")
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if di.Mode()&0o002 != 0 {
		return fmt.Errorf("binary's directory is world-writable")
	}
	return nil
}

// scrubbedEnv builds the subprocess environment from the backend's allowlist
// only — nothing inherited beyond what the backend declares it needs.
func (b *backend) scrubbedEnv() []string {
	var env []string
	for _, name := range b.allowEnv {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

func substVars(s template.SourceSpec, instance string) map[string]string {
	vars := map[string]string{"instance": instance}
	for k, v := range s.Params {
		vars[k] = v
	}
	return vars
}

// capWriter discards anything past max, so a runaway backend can't exhaust
// memory. It reports the capped length via n but never grows past max.
type capWriter struct {
	w   *bytes.Buffer
	max int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if room := c.max - c.w.Len(); room > 0 {
		if len(p) > room {
			c.w.Write(p[:room])
		} else {
			c.w.Write(p)
		}
	}
	return len(p), nil // pretend full consumption so the process isn't killed by EPIPE
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}
