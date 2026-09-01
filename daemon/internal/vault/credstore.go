package vault

import (
	"errors"
	"fmt"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// The credential store is reached through these, not through keyring.Get/Set
// directly, so tests can produce the failures that matter here. A store that is
// present but unusable — a locked collection, a dead session bus, an ACL that
// refuses — is the case this file exists for, and the in-memory keyring the test
// binary otherwise runs on can only ever be absent or working.
var (
	keyringGetRaw = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

// credentialStoreTimeout bounds a single read of the OS credential store.
//
// Generous on purpose: a first unlock prompt on a desktop can legitimately take
// seconds, and turning that into a failure would be worse than the wait. What
// this stops is the wait that never ends.
// A var, not a const, only so the test that guards the bound can shorten it —
// nothing in the product changes it.
var credentialStoreTimeout = 10 * time.Second

// keyringGet reads the credential store, but never forever.
//
// go-keyring's Linux backend does not return an error when there is no session
// bus — it forks its own dbus-launch and BLOCKS. So `akasha status` printed its
// health JSON and then hung, with rc=124 at 30s and a healthy daemon behind it,
// on any shell without DBUS_SESSION_BUS_ADDRESS. `akasha agent list` hung with
// no output at all. Both are the second terminal a user opens after following
// the Linux setup instructions.
//
// reportAgentHealth's comment claimed the check was "silently skipped" if the
// vault could not be opened. That was true of an error and false of a hang, and
// the difference is the whole bug: code written to tolerate a failure gets a
// stall instead, and a stall has no branch to take.
//
// Bounding it here rather than at each call site means a path added later
// inherits the property instead of rediscovering it.
// KeychainRead is keyringGet for callers outside this package.
//
// It exists because there was a second reader that did not have the bound: the
// sandbox self-test wired keyring.Get directly, so `akasha run` and
// `akasha sandbox doctor` printed nothing at all for about four minutes on any
// shell without DBUS_SESSION_BUS_ADDRESS — the flagship command, silent, on the
// state the Linux setup instructions leave you in. The bound described below
// was ten lines away and unreachable.
//
// Every path that touches the OS credential store goes through this package's
// two functions, so the property is inherited rather than remembered.
func KeychainRead(service, account string) (string, error) { return keyringGet(service, account) }

func keyringGet(service, account string) (string, error) {
	type result struct {
		value string
		err   error
	}
	// Buffered so the goroutine can finish and exit even after a timeout — an
	// unbuffered channel would leak it against a store that answers late.
	ch := make(chan result, 1)
	go func() {
		v, err := keyringGetRaw(service, account)
		ch <- result{v, err}
	}()

	select {
	case r := <-ch:
		return r.value, r.err
	case <-time.After(credentialStoreTimeout):
		return "", fmt.Errorf("the credential store did not answer within %s.\n"+
			"  It is not refusing — it is not responding, which usually means there is no\n"+
			"  session bus for it to reach.\n%s",
			credentialStoreTimeout, credentialStoreHelp)
	}
}

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
    (over the D-Bus session bus). Use gnome-keyring: it is the only provider
    verified to serve org.freedesktop.secrets on the distros below. Install one
    and UNLOCK IT BEFORE akasha first runs — a collection akasha has already woken
    up locked will not unlock in place:
        sudo apt install gnome-keyring dbus-x11   # dnf/apk/pacman: gnome-keyring dbus
        pkill -f gnome-keyring-daemon             # ONLY if akasha already failed once
        dbus-run-session -- sh -c '
          stty -echo; printf "keyring password: "; read P; stty echo; echo
          printf %s "$P" | gnome-keyring-daemon --unlock
          akasha start'
    --unlock reads the password from stdin until EOF, so it must be piped in:
    run without it and it waits forever, even on a terminal.
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
