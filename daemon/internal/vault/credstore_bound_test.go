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
	t.Cleanup(func() {
		close(blocked)
		keyringGetRaw, credentialStoreTimeout = realGet, realTimeout
	})

	// A store that never answers: the shape of a missing session bus.
	keyringGetRaw = func(string, string) (string, error) {
		<-blocked
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
