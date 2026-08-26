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
	keyringGet = keyring.Get
	keyringSet = keyring.Set
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
