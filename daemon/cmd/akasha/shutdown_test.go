package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

// GUARANTEE: `akasha start` stops on a signal instead of being killed by one.
//
// The daemon registered no handler, so launchd, systemd and ^C all killed it
// outright and not one deferred Close ran. The one that matters is the vault's:
// SQLite in WAL mode leaves every write in vault.db-wal until a checkpoint, so
// an un-checkpointed vault.db is a 4 KB header and every copy of it — backup,
// machine move, `uninstall --export` — carries away an empty vault.
func TestShutdownSignalsAreRegistered(t *testing.T) {
	// Safety net. Registering the same signals here first keeps the Go runtime's
	// handler installed, so a regression in shutdownSignals surfaces as this
	// test timing out rather than as SIGTERM killing the whole test binary.
	guard := make(chan os.Signal, 8)
	signal.Notify(guard, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(guard)

	sigc := shutdownSignals()
	defer signal.Stop(sigc)

	for _, want := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		if err := syscall.Kill(os.Getpid(), want); err != nil {
			t.Fatalf("raise %v: %v", want, err)
		}
		select {
		case got := <-sigc:
			if got != want {
				t.Fatalf("shutdown channel got %v, want %v", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%v never reached the daemon's shutdown channel — the daemon would be "+
				"killed outright, running none of its defers and leaving the WAL unchecked", want)
		}
	}
}

// The wait has to end when a signal arrives, or registering for it changed
// nothing. A regression here shows up as this test hanging, which is exactly
// how the bug behaved in production.
func TestServeUntilShutdownReturnsOnSignal(t *testing.T) {
	var wg sync.WaitGroup
	stopListeners := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-stopListeners // stands in for a listener that serves until told to stop
	}()

	shutdownCalled := make(chan struct{})
	shutdown := func(context.Context) {
		close(shutdownCalled)
		close(stopListeners)
	}

	sigc := make(chan os.Signal, 1)
	returned := make(chan struct{})
	go func() {
		serveUntilShutdown(&wg, sigc, shutdown, shutdownGrace)
		close(returned)
	}()

	sigc <- syscall.SIGTERM
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown never returned after SIGTERM — startCmd's deferred " +
			"vault Close would never run, so the WAL would never be checkpointed")
	}
	select {
	case <-shutdownCalled:
	default:
		t.Fatal("listeners were never asked to drain")
	}
}

// The other exit: every listener failed to bind and gave up on its own. That
// must return too, and without waiting on a signal that is never coming.
func TestServeUntilShutdownReturnsWhenListenersStop(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go wg.Done()

	returned := make(chan struct{})
	go func() {
		serveUntilShutdown(&wg, make(chan os.Signal), func(context.Context) {
			t.Error("shutdown must not be called when the listeners already stopped")
		}, shutdownGrace)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown blocked after every listener had stopped")
	}
}

// GUARANTEE: a stop always ends the process, even when a listener refuses to
// come back.
//
// Waiting on the listeners unconditionally is worse than not trapping the
// signal at all. The handler swallows SIGTERM, SIGINT and SIGHUP from the
// moment it is installed, so a wait that never ends leaves a daemon that still
// answers on the socket and the loopback port — still handing out credentials —
// with no signal left that can stop it and an operator who has been told it
// shut down. Only SIGKILL ends it, and SIGKILL is the one exit that skips the
// vault Close this whole path exists to reach.
//
// Server.Shutdown missing a listener is not hypothetical: a listener that
// registers itself just after Shutdown has walked its list is never told to
// stop (see server.serve). That race is fixed at the source; this is the belt
// to its braces, so no future way of losing a listener can wedge the daemon.
func TestServeUntilShutdownGivesUpOnAListenerThatNeverStops(t *testing.T) {
	var wg sync.WaitGroup
	stuck := make(chan struct{})
	defer close(stuck)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-stuck // a listener Shutdown never reached
	}()

	sigc := make(chan os.Signal, 1)
	returned := make(chan struct{})
	go func() {
		// A shutdown that stops nothing — exactly what Server.Shutdown does for
		// a listener it does not know about.
		serveUntilShutdown(&wg, sigc, func(context.Context) {}, 50*time.Millisecond)
		close(returned)
	}()

	sigc <- syscall.SIGTERM
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown never returned though the daemon had been asked to stop — " +
			"the process would keep serving credentials with SIGTERM already trapped, and " +
			"only SIGKILL, which skips the vault Close, could end it")
	}
}
