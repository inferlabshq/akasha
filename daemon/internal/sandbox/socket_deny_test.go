package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A denied tree must take its unix sockets with it.
//
// On darwin a file-read/file-write deny does NOT cover connect(2): measured on
// macOS 13, a socket inside a `(deny file-read* file-write* (subpath D))` stayed
// connectable, which left the daemon socket, Docker Desktop's
// ~/.docker/run/docker.sock and gpg-agent's socket in ~/.gnupg reachable from
// every run. bubblewrap masks the directory itself, so Linux never had the gap;
// this test runs the real backend on both and must hold on both.
//
// The allowed-back socket in the same tree must stay reachable: that is the
// broker's own door, and a fix that shuts it would make every run useless.
func TestEnforceDeniedTreeHidesItsSockets(t *testing.T) {
	requireSandbox(t)
	akashaBin := buildProbeBinary(t)

	// Short path: unix socket paths cap near 104 bytes.
	dir, err := os.MkdirTemp("/tmp", "akdn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	listen := func(name string) string {
		p := filepath.Join(dir, name)
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		return p
	}
	listen("daemon.sock")       // must be unreachable from inside
	door := listen("door.sock") // allowed back, must stay reachable

	spec := specFor(t, dir).AllowSocketPath(door)
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := SelfTest(spec, akashaBin); err != nil {
		t.Fatalf("a socket inside a denied tree was reachable, or the allowed-back one was not: %v", err)
	}
}

// The renderer half, which runs on the Linux CI runner too: every DenyAll rule
// carries a network-outbound deny for the same path, emitted with the other
// denies (before every allow-back), and write-only rules carry none, since a
// write seal says nothing about connecting.
func TestSBPLDeniesSocketsInDeniedPaths(t *testing.T) {
	s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil).
		AllowSocketPath("/Users/me/.akasha/akasha.sock")
	profile := darwinProfile(t, s)

	want := `(deny network-outbound (subpath "/Users/me/.akasha"))`
	i := strings.Index(profile, want)
	if i == -1 {
		t.Fatalf("the data directory's sockets are not denied:\n%s", profile)
	}
	back := strings.Index(profile, `(allow network-outbound (literal "/Users/me/.akasha/akasha.sock"))`)
	if back == -1 || back < i {
		t.Fatalf("the allowed-back socket must come after the deny it punches through:\n%s", profile)
	}

	for _, r := range s.Deny {
		if r.Mode != DenyWrite || !r.appliesTo("darwin") {
			continue
		}
		if strings.Contains(profile, "(deny network-outbound (literal "+mustQuote(t, r.Path)+"))") ||
			strings.Contains(profile, "(deny network-outbound (subpath "+mustQuote(t, r.Path)+"))") {
			t.Fatalf("write-only rule %s gained a connect deny:\n%s", r.Path, profile)
		}
	}
}

func mustQuote(t *testing.T, p string) string {
	t.Helper()
	q, err := sbplString(p)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
