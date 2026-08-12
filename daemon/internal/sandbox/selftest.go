package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Every generated-profile sandbox shares one failure mode: the profile renders,
// the launcher accepts it, the child starts — and it is not enforcing what you
// think. A mistyped mach service name, a subpath with a trailing slash, a
// bubblewrap flag the kernel silently ignored: all of them look exactly like
// success. Nothing in Wrap can detect it, because Wrap only builds argv.
//
// So the sandbox proves itself on every launch. SelfTest runs the akasha binary
// inside the very profile about to be used and has it attempt the reads the
// sandbox is supposed to prevent. If any of them yields secret bytes, the launch
// is refused.
//
// The criterion is deliberately "NO SECRET BYTES", not a particular errno.
// Linux and macOS disagree here and always will: a denied file reads as EMPTY
// under bubblewrap (it is a bind-mount of /dev/null) and returns EPERM under
// seatbelt. Asserting an errno would make the test platform-specific for no
// security gain — what matters is that the agent cannot obtain the contents.

// probe is the plan handed to the child.
//
// It travels over STDIN rather than argv or the environment. Both of those are
// readable by any same-user process via ps and /proc, and this plan names every
// path we are protecting — publishing that list to the machine in order to test
// that the list is protected would be self-defeating.
type probe struct {
	DenyPaths    []string `json:"deny_paths"`
	AllowSockets []string `json:"allow_sockets"`
	Keychain     *struct {
		Service string `json:"service"`
		Account string `json:"account"`
	} `json:"keychain,omitempty"`
}

// probeResult is what the child reports back.
type probeResult struct {
	Leaks             []string `json:"leaks"`              // paths that yielded bytes
	UnreachableSocket []string `json:"unreachable_socket"` // doors that were shut by mistake
	KeychainReachable bool     `json:"keychain_reachable"`
	Err               string   `json:"err,omitempty"`
}

// SelfTestTimeout bounds the probe. It runs on every launch, so it must be
// cheap; one fork of an already-warm binary is a few tens of milliseconds.
const SelfTestTimeout = 20 * time.Second

// SelfTest verifies that spec is actually enforced, by running akashaBin's
// hidden `sandbox-selftest` command inside it.
//
// akashaBin must be the absolute path to this binary. A non-nil error means the
// sandbox is NOT enforcing what the spec claims, and the caller must refuse to
// launch — a sandbox believed-but-not-enforced is worse than none, because it
// is the one you stop checking.
func SelfTest(spec Spec, akashaBin string) error {
	p := probe{}

	// Only probe paths that EXIST on the host.
	//
	// Without this the test is worse than useless: vault.db-shm is absent
	// between SQLite checkpoints, so probing it would report "cannot read —
	// enforced" on a machine where nothing is enforced at all. A self-test that
	// passes for the wrong reason is exactly the failure it exists to catch.
	for _, r := range spec.Deny {
		if r.Tree {
			continue // a directory read is checked via its contents below
		}
		if allowedBack(spec, r.Path) {
			continue
		}
		if _, err := os.Stat(r.Path); err == nil {
			p.DenyPaths = append(p.DenyPaths, r.Path)
		}
	}
	for _, r := range spec.Deny {
		if !r.Tree {
			continue
		}
		if ents, err := os.ReadDir(r.Path); err == nil {
			for _, e := range ents {
				if !e.Type().IsRegular() {
					continue
				}
				candidate := r.Path + "/" + e.Name()
				// Skip a file the spec deliberately allows back.
				//
				// The deny-default islands intentionally punch holes: ~/.ssh is
				// denied as a tree but config, known_hosts and the public keys
				// are readable so ssh still works. Probing one of those would
				// report a "leak" for a file we chose to expose — a false alarm
				// that, on a mechanism whose whole job is to be believed, is
				// nearly as damaging as a missed one. It teaches people to pass
				// --no-sandbox.
				if allowedBack(spec, candidate) {
					continue
				}
				p.DenyPaths = append(p.DenyPaths, candidate)
				break // one witness per tree is enough, and keeps the probe cheap
			}
		}
	}
	p.AllowSockets = append(p.AllowSockets, spec.AllowSocket...)

	if spec.DenyKeychain {
		svc, acct := keychainProbeTarget()
		if svc != "" {
			p.Keychain = &struct {
				Service string `json:"service"`
				Account string `json:"account"`
			}{svc, acct}
		}
	}

	// Nothing to prove: no existing secret to read, no door to check. Report it
	// rather than passing silently — "the sandbox was verified" and "there was
	// nothing to verify" are different claims.
	if len(p.DenyPaths) == 0 && len(p.AllowSockets) == 0 && p.Keychain == nil {
		return nil
	}

	plan, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("sandbox self-test: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), SelfTestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, akashaBin, "sandbox-selftest")
	cmd.Stdin = bytes.NewReader(plan)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := Wrap(spec, cmd); err != nil {
		return fmt.Errorf("sandbox self-test could not be wrapped: %w", err)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sandbox self-test did not complete (%v): %s\n"+
			"The sandbox could not be verified, so the launch is refused.", err, strings.TrimSpace(errb.String()))
	}

	var res probeResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return fmt.Errorf("sandbox self-test returned unreadable output (%v); refusing to launch", err)
	}
	if res.Err != "" {
		return fmt.Errorf("sandbox self-test failed: %s", res.Err)
	}

	var problems []string
	if len(res.Leaks) > 0 {
		problems = append(problems, fmt.Sprintf(
			"the sandbox did NOT block these, so the agent could read them:\n    %s",
			strings.Join(res.Leaks, "\n    ")))
	}
	if res.KeychainReachable {
		problems = append(problems, "the OS keychain was still reachable from inside the sandbox")
	}
	if len(res.UnreachableSocket) > 0 {
		// The opposite failure, and just as important: hardening that broke the
		// one door the agent needs. Without this check the sandbox would look
		// perfect and every credential operation would fail.
		problems = append(problems, fmt.Sprintf(
			"the daemon socket was NOT reachable from inside the sandbox, so no credential could be brokered:\n    %s",
			strings.Join(res.UnreachableSocket, "\n    ")))
	}
	if len(problems) > 0 {
		return fmt.Errorf("sandbox self-test failed — refusing to launch:\n  %s",
			strings.Join(problems, "\n  "))
	}
	return nil
}

// RunSelfTestChild is the child half, invoked as `akasha sandbox-selftest`. It
// reads a plan from stdin, attempts each forbidden read, and reports JSON.
//
// It is deliberately not a cobra command with flags: the plan arrives on stdin
// precisely so it never appears in ps.
func RunSelfTestChild(stdin *os.File, stdout *os.File, keychainGet func(service, account string) (string, error)) error {
	var p probe
	if err := json.NewDecoder(stdin).Decode(&p); err != nil {
		return writeResult(stdout, probeResult{Err: "could not read the probe plan: " + err.Error()})
	}

	var res probeResult
	for _, path := range p.DenyPaths {
		// "Leak" means we obtained CONTENT. An empty read is what a bubblewrap
		// deny looks like; an error is what a seatbelt deny looks like. Both are
		// enforcement.
		b, err := os.ReadFile(path)
		if err == nil && len(b) > 0 {
			res.Leaks = append(res.Leaks, path)
		}
	}
	for _, sock := range p.AllowSockets {
		if err := dialable(sock); err != nil {
			res.UnreachableSocket = append(res.UnreachableSocket, fmt.Sprintf("%s (%v)", sock, err))
		}
	}
	if p.Keychain != nil && keychainGet != nil {
		if _, err := keychainGet(p.Keychain.Service, p.Keychain.Account); err == nil {
			res.KeychainReachable = true
		}
	}
	return writeResult(stdout, res)
}

func writeResult(w *os.File, res probeResult) error {
	return json.NewEncoder(w).Encode(res)
}

// allowedBack reports whether path is covered by an allow-back rule, so the
// probe does not flag a hole the spec opened on purpose.
func allowedBack(spec Spec, path string) bool {
	covered := func(list []string) bool {
		for _, a := range list {
			if path == a || strings.HasPrefix(path, strings.TrimSuffix(a, "/")+"/") {
				return true
			}
		}
		return false
	}
	return covered(spec.AllowRead) || covered(spec.AllowWrite) || covered(spec.AllowSocket)
}
