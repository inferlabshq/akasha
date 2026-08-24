package sandbox

import (
	"strings"
	"testing"
)

// argvHasBind reports whether argv contains `--bind /dev/null <path>` in order.
func argvHasBind(argv []string, path string) bool {
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--bind" && argv[i+1] == "/dev/null" && argv[i+2] == path {
			return true
		}
	}
	return false
}

func argvHasTmpfs(argv []string, path string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--tmpfs" && argv[i+1] == path {
			return true
		}
	}
	return false
}

// DenyKeychain masked ~/.local/share/keyrings and stopped there — but the vault
// does not read those files. It calls org.freedesktop.secrets over the D-Bus
// session bus, served by a daemon OUTSIDE the sandbox, and under --dev-bind / /
// that socket passed straight through. The agent could ask for the vault key by
// exactly the route the daemon uses, on a profile that reported success.
func TestDenyKeychainClosesTheSessionBus(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")

	argv, err := bwrapArgv(Spec{DenyKeychain: true}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHasBind(argv, "/run/user/1000/bus") {
		t.Fatalf("the session bus was left reachable:\n%s", strings.Join(argv, " "))
	}
	// The files still go too — a keyring database readable directly is its own
	// path to the same secret.
	if !argvHasTmpfs(argv, "/run/user/1000/keyring") {
		t.Errorf("gnome-keyring's control socket directory was not masked")
	}
}

// Without DenyKeychain nothing is masked: the bus mask is a consequence of
// closing the credential store, not an unconditional policy. It costs the child
// every other session-bus service, so it must not apply where it was not asked
// for.
func TestSessionBusSurvivesWithoutDenyKeychain(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")

	argv, err := bwrapArgv(Spec{}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if argvHasBind(argv, "/run/user/1000/bus") {
		t.Fatal("the session bus was masked on a spec that never asked to deny the keychain")
	}
}

// The systemd default is the live socket even when the variable is unset, and
// a client falls back to it. Masking only what the variable names would leave
// that fallback open.
func TestSessionBusFallbacksAreMasked(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")

	argv, err := bwrapArgv(Spec{DenyKeychain: true}, "/usr/bin/bwrap", []string{"agent"})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHasBind(argv, "/run/user/1000/bus") {
		t.Fatalf("the XDG_RUNTIME_DIR fallback bus was not masked:\n%s", strings.Join(argv, " "))
	}
}

func TestDBusAddressParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		want []string
	}{
		{"systemd", "unix:path=/run/user/1000/bus", []string{"/run/user/1000/bus"}},
		{"with guid", "unix:path=/run/user/1000/bus,guid=deadbeef", []string{"/run/user/1000/bus"}},
		{"percent-encoded", "unix:path=/run/user/1000/my%20bus", []string{"/run/user/1000/my bus"}},
		{"several addresses", "unix:path=/run/a;unix:path=/run/b", []string{"/run/a", "/run/b"}},
		// Abstract sockets live in the network namespace, not the filesystem:
		// there is nothing for a mount to cover. Skipped, never guessed at.
		{"abstract", "unix:abstract=/tmp/dbus-Xyz,guid=abc", nil},
		{"tcp", "tcp:host=127.0.0.1,port=1234", nil},
		{"empty", "", nil},
		{"malformed escape", "unix:path=/run/user/%zz", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dbusUnixPaths(tc.addr)
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}

// These paths come from the ENVIRONMENT, unlike everything in the Spec, so they
// get the same validation. `--bind /dev/null /` would be a very bad way to
// learn that.
func TestSessionBusPathsAreValidated(t *testing.T) {
	for _, addr := range []string{
		"unix:path=/",
		"unix:path=/bus",             // too shallow to deny safely
		"unix:path=/etc/../etc/bus",  // not clean
		"unix:path=relative/bus",     // not absolute
		"unix:path=/nowhere/near/it", // outside the allowed roots
	} {
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
		t.Setenv("XDG_RUNTIME_DIR", "")
		for _, p := range linuxSecretServicePaths() {
			if err := validPath(p, "session-bus"); err != nil {
				t.Errorf("%s produced an unvalidated mount path %q: %v", addr, p, err)
			}
		}
	}
}

// Every mount argument must survive Validate's rule, whatever its origin.
func TestDescribeForLinuxStaysValid(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")

	out, err := DescribeFor("linux", Surface(t.TempDir()+"/.akasha", t.TempDir()+"/run", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/run/user/1000/bus") {
		t.Error("the rendered profile does not show the session bus being closed")
	}
}
