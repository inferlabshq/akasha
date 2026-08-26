package vault

import (
	"errors"
	"fmt"

	keyring "github.com/zalando/go-keyring"
)

// The credential store is reached through these, not through keyring.Get/Set
// directly, so tests can produce the failures that matter here. A store that is
// present but unusable — a locked collection, a dead session bus, an ACL that
// refuses — is the case this file exists for, and the in-memory keyring the test
// binary otherwise runs on can only ever be absent or working.
var (
	keyringGet    = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

// credentialStoreHelp is the prerequisite that decides whether akasha works at
// all on Linux, and the ordering rule that no error message can teach you.
//
// The vault key goes into the OS credential store and there is no on-disk
// fallback, so on a bare Linux box the first `akasha start` is also the first
// thing that fails, with a raw D-Bus string — `exec: "dbus-launch": executable
// file not found in $PATH` — which names neither the requirement nor a remedy.
// Nothing in the README, getting-started or the installer mentioned it either.
//
// The second half is the part that is not discoverable at all. Once akasha has
// D-Bus-activated a keyring that has no unlocked collection, running the obvious
// fix afterwards does NOT recover: the already-running daemon tries to raise a
// graphical prompter, fails, and every later attempt fails the same way. Only
// killing it and unlocking before anything touches the bus works. A user who
// follows the documented sequence on a headless box, a devcontainer, WSL or CI
// hits exactly that order, which is why the kill is spelled out rather than left
// to be deduced.
//
// Both platforms are named unconditionally rather than branched on runtime.GOOS,
// matching the guards in resolveKeys: the platform is the one thing the reader
// already knows, and branching hides the other half from anyone diagnosing a
// machine remotely.
const credentialStoreHelp = `  Linux: akasha keeps the vault key in the freedesktop Secret Service
    (gnome-keyring, KWallet or KeePassXC, over the D-Bus session bus). Install one
    and UNLOCK IT BEFORE akasha first runs — a collection akasha has already woken
    up locked will not unlock in place:
        sudo apt install gnome-keyring dbus-x11   # dnf/apk/pacman: gnome-keyring dbus
        pkill -f gnome-keyring-daemon             # ONLY if akasha already failed once
        dbus-run-session -- sh -c 'gnome-keyring-daemon --unlock; akasha start'
    On a desktop, logging in unlocks the login keyring for you.
  macOS: unlock your login keychain and allow access when prompted.`

// ProbeCredentialStore reports whether this machine's credential store can be
// read at all, so a caller can refuse before doing anything a failure would
// leave half-done.
//
// Absence of a key is a pass: a fresh machine has none, and so does a healthy
// store on first run. Anything else — the store is missing, locked, or the read
// was refused — is a fail, because those are the states in which the vault
// cannot be opened OR created. This is the same distinction resolveKeys makes
// between keyring.ErrNotFound and every other error, for the same reason: not
// knowing whether a key is there has to be treated like knowing one is.
func ProbeCredentialStore() error {
	_, err := keyringGet(keyringService, keyringMLKEMSK)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("this machine's credential store could not be read (%w).\n"+
		"  Akasha keeps your vault key there, so nothing can be vaulted until it works.\n%s",
		err, credentialStoreHelp)
}

// probeAccount is the throwaway item StoreIsReachable round-trips. It lives
// under the SAME service as the vault key so the probe exercises the store the
// vault actually uses, not a different one that might be healthy.
const probeAccount = "reachability-probe"

// StoreIsReachable answers the one question ErrNotFound cannot: is this
// credential store WORKING, or merely answering?
//
// It matters because "no key here" is the fact the new-vault guard bets the
// user's whole vault on, and on macOS that fact is not reliably observable.
// go-keyring's darwin backend shells out to /usr/bin/security and maps ANY
// output containing "could not be found" to ErrNotFound — which the `security`
// CLI emits both for a missing ITEM and for a keychain it cannot reach. So an
// unreachable login keychain is byte-identical to a fresh machine, and a guard
// that reads ErrNotFound as "safe to create" will mint a new key over a real one
// exactly when the keychain is locked. That is the state launchd starts the
// daemon in at login.
//
// A write/read/delete round trip does not depend on any error string, so it
// answers the same way on every platform and cannot be fooled by a backend that
// reports absence when it means inaccessible. It writes only a throwaway value
// under its own account name, and removes it again.
func StoreIsReachable() error {
	const canary = "akasha-reachability-probe"
	if err := keyringSet(keyringService, probeAccount, canary); err != nil {
		return fmt.Errorf("could not write to the credential store: %w", err)
	}
	// Best-effort cleanup: a leftover probe item is harmless (it is not a
	// secret and the next probe overwrites it), and failing the probe because
	// the DELETE failed would be a false alarm.
	defer keyringDelete(keyringService, probeAccount)

	got, err := keyringGet(keyringService, probeAccount)
	if err != nil {
		return fmt.Errorf("could not read back from the credential store: %w", err)
	}
	if got != canary {
		// A store that returns something other than what was just written is
		// not one to trust a vault key to.
		return fmt.Errorf("the credential store returned a different value than was written to it")
	}
	return nil
}
