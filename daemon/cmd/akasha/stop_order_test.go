package main

import (
	"io"
	"strings"
	"testing"
)

// The service manager is told before the daemon is asked to stop; otherwise
// launchd's KeepAlive restarts it and the stop reports a refusal. Seen on
// every fresh-Mac `akasha uninstall`.
func TestStopUnloadsTheServiceManagerFirst(t *testing.T) {
	var order []string
	up := true
	d := stopDeps{
		stopService: func() (bool, string) { order = append(order, "service"); up = false; return true, "unloaded" },
		reachable:   func() bool { return up },
		shutdown:    func() error { order = append(order, "shutdown"); up = false; return nil },
		waitGone:    func() bool { return !up },
		hint:        func() string { return "" },
	}
	if err := stopDaemonCleanly(d, false, io.Discard); err != nil {
		t.Fatalf("a clean stop reported: %v", err)
	}
	if strings.Join(order, ",") != "service" {
		t.Fatalf("want the service manager first and no shutdown for a daemon it stopped, got %v", order)
	}
}

// A daemon the service manager did not own still gets the /shutdown request.
func TestStopFallsBackToShutdown(t *testing.T) {
	var order []string
	up := true
	d := stopDeps{
		stopService: func() (bool, string) { order = append(order, "service"); return false, "" },
		reachable:   func() bool { return up },
		shutdown:    func() error { order = append(order, "shutdown"); up = false; return nil },
		waitGone:    func() bool { return !up },
		hint:        func() string { return "" },
	}
	if err := stopDaemonCleanly(d, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "service,shutdown" {
		t.Fatalf("got %v", order)
	}
}

// A caller aimed at another --socket/--db must not touch the default service.
func TestTargetedStopLeavesTheServiceManagerAlone(t *testing.T) {
	up := true
	d := stopDeps{
		stopService: func() (bool, string) { t.Fatal("touched the default service for a targeted stop"); return false, "" },
		reachable:   func() bool { return up },
		shutdown:    func() error { up = false; return nil },
		waitGone:    func() bool { return !up },
		hint:        func() string { return "" },
	}
	if err := stopDaemonCleanly(d, true, io.Discard); err != nil {
		t.Fatal(err)
	}
}
