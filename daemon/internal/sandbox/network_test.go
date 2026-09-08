package sandbox

import (
	"strings"
	"testing"
)

// `--no-network` has to remove IP networking without taking the unix socket
// akasha brokers over with it. The two platforms need different primitives to
// achieve that, and the obvious spelling is wrong on one of them.
//
// Both directions are rendered from either host, which is what DescribeFor is
// for — the macOS profile is the generated-code surface and therefore the one
// most worth testing.
func TestDenyNetworkRendersPerPlatform(t *testing.T) {
	const sock = "/tmp/akasha-run.sock"

	render := func(t *testing.T, goos string, deny bool) string {
		t.Helper()
		spec := Spec{DenyNetwork: deny}.AllowSocketPath(sock)
		out, err := DescribeFor(goos, spec)
		if err != nil {
			t.Fatalf("render %s: %v", goos, err)
		}
		return out
	}

	t.Run("linux unshares the network namespace", func(t *testing.T) {
		on := render(t, "linux", true)
		off := render(t, "linux", false)

		if !strings.Contains(on, "--unshare-net") {
			t.Errorf("--no-network did not unshare the network namespace:\n%s", on)
		}
		if strings.Contains(off, "--unshare-net") {
			t.Error("a run that did not ask for it lost its network")
		}
		// PATHNAME unix sockets are not namespaced by the network namespace, so
		// the broker socket must still be bound. That property is what makes
		// this mode possible at all — measured before it was built.
		if !strings.Contains(on, sock) {
			t.Errorf("the broker socket was not bound alongside the namespace:\n%s", on)
		}
	})

	t.Run("darwin denies IP, not all network", func(t *testing.T) {
		on := render(t, "darwin", true)
		off := render(t, "darwin", false)

		for _, want := range []string{
			`(deny network-outbound (remote ip "*:*"))`,
			"(deny network-inbound)",
		} {
			if !strings.Contains(on, want) {
				t.Errorf("profile is missing %q:\n%s", want, on)
			}
		}

		// The trap this test exists for. `(deny network*)` also denies AF_UNIX,
		// and a later `(allow network-outbound (literal …))` does NOT bring it
		// back — measured on darwin, the pathname socket stayed refused with a
		// PermissionError. That spelling would silently take akasha's own
		// broker socket with it, and the run would fail to broker anything.
		if strings.Contains(on, "(deny network*)") {
			t.Error("profile denies all network, which also denies the unix socket akasha brokers over")
		}
		if !strings.Contains(on, `(allow network-outbound (literal "`+sock+`"))`) {
			t.Errorf("the broker socket allow did not survive next to the denies:\n%s", on)
		}

		if strings.Contains(off, "network-inbound") {
			t.Error("a run that did not ask for it lost its network")
		}
	})
}
