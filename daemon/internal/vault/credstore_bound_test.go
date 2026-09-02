package vault

import (
	"strings"
	"testing"
	"time"
)

// Every read of the OS credential store must be bounded, including the ones
// made from outside this package.
//
// The bound existed and had a second reader that bypassed it: the sandbox
// self-test wired keyring.Get directly, so `akasha run` and `akasha sandbox
// doctor` produced no output at all — not on stdout, not on stderr — for about
// four minutes per invocation on any shell without DBUS_SESSION_BUS_ADDRESS.
// go-keyring's Linux backend forks its own dbus-launch and blocks instead of
// returning an error, so there is no failure for a caller to handle; there is
// only silence, which is indistinguishable from wedged.
func TestKeychainReadIsBounded(t *testing.T) {
	realGet, realTimeout := keyringGetRaw, credentialStoreTimeout
	blocked := make(chan struct{})
	// The probe goroutine OUTLIVES the call it was made for — that is the
	// property under test — so it is still holding these globals when the test
	// ends. Restoring them without waiting is a real data race, and the race
	// detector says so. released is the happens-before edge.
	released := make(chan struct{})
	t.Cleanup(func() {
		close(blocked)
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Error("the probe goroutine never returned; globals left as the test set them")
		}
		keyringGetRaw, credentialStoreTimeout = realGet, realTimeout
	})

	// A store that never answers: the shape of a missing session bus.
	keyringGetRaw = func(string, string) (string, error) {
		<-blocked
		close(released)
		return "", nil
	}
	credentialStoreTimeout = 50 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := KeychainRead("svc", "acct")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a store that never answers must surface an error, not a value")
		}
		// The message has to name the cause, or the reader is left staring at
		// a timeout with nothing to do about it.
		if !strings.Contains(err.Error(), "session bus") {
			t.Errorf("the error should name the usual cause, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("KeychainRead never returned — the bound is gone, and with it the only thing " +
			"stopping `akasha run` from going silent for four minutes")
	}
}

// The same bound on the WRITE path, which is the one that actually hung.
//
// Measured on macOS before this existed: `akasha start` with a freshly built
// binary printed its banner and stopped dead, main thread parked in wait4 on a
// `/usr/bin/security -i` child waiting for a keychain prompt nobody could
// answer. macOS keys a keychain item's ACL to the code identity that created
// it, so a rebuilt or re-signed binary is a different application and the item
// is withheld — the same ACL break this project has already lost a vault to.
//
// A write is the operation the OS most wants to ask a human about, so it is the
// one that most needed the bound and the one that did not have it.
func TestKeychainWriteIsBounded(t *testing.T) {
	realSet, realTimeout := keyringSetRaw, credentialStoreTimeout
	blocked := make(chan struct{})
	released := make(chan struct{})
	t.Cleanup(func() {
		close(blocked)
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Error("the write goroutine never returned")
		}
		// Restoring the RAW hook, never the wrapper: aliasing the wrapper to
		// itself makes every later call recurse, which shows up as the whole
		// package taking minutes instead of seconds.
		keyringSetRaw, credentialStoreTimeout = realSet, realTimeout
	})

	keyringSetRaw = func(string, string, string) error {
		<-blocked
		close(released)
		return nil
	}
	credentialStoreTimeout = 50 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- keyringSet("svc", "acct", "secret") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a store that never accepts the write must surface an error")
		}
		if !strings.Contains(err.Error(), "did not accept a write") {
			t.Errorf("the error should say what failed, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keyringSet never returned — a keychain prompt would hang the daemon forever")
	}
}
