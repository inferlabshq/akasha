package sandbox

import (
	"fmt"
	"net"
	"time"
)

// dialable reports whether a unix socket can actually be connected to.
//
// This is the "we hardened it until it stopped working" check. Every other
// assertion in the self-test looks for something that should FAIL; this one
// looks for the single thing that must still SUCCEED. Without it a profile that
// denied everything — including the daemon socket — would pass the self-test
// perfectly and then break every credential operation at runtime, which is the
// failure mode most likely to get the sandbox turned off.
func dialable(path string) error {
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	return nil
}

// keychainProbeTarget is overridden by the daemon build so the self-test asks
// about the SAME keychain item the vault uses. Probing a different item would
// pass while the real key stayed reachable.
var keychainProbeTarget = func() (service, account string) { return "", "" }

// SetKeychainProbeTarget wires the vault's real identifiers in. Called once from
// main; kept as a hook so this package does not import the vault.
func SetKeychainProbeTarget(fn func() (string, string)) {
	if fn != nil {
		keychainProbeTarget = fn
	}
}

// keychainProbeRead lets the PARENT confirm the item is readable before asking
// the child to try reading it.
//
// Without it the keychain check could only ever say "the read failed", which is
// what a missing item and a working sandbox both look like — so on a host with
// no vault key it passed having proved nothing. Same shape as the existing hook,
// and same reason it is a hook: this package must not import the vault.
var keychainProbeRead func(service, account string) (string, error)

// SetKeychainProbeReader wires the reader in. Called once from main, alongside
// SetKeychainProbeTarget.
func SetKeychainProbeReader(fn func(service, account string) (string, error)) {
	if fn != nil {
		keychainProbeRead = fn
	}
}

var _ = fmt.Sprintf
