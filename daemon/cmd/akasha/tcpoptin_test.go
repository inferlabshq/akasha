package main

import (
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/server"
)

// With the socket down and no opt-in, the CLI must not reach for the shared
// port: whatever holds it would receive this user's key. Reported by Sam
// Andrews, who logged the key arriving at a stand-in listener.
func TestDefaultInvocationDoesNotFallBackToTCP(t *testing.T) {
	t.Setenv("AKASHA_AGENT_KEY", "ak_DUMMY_NOT_A_REAL_KEY")
	t.Setenv(server.TCPOptInEnv, "")
	sock := "/tmp/akasha-no-such-daemon.sock"

	for name, call := range map[string]func() error{
		"GET":  func() error { _, err := daemonGet(sock, "/health"); return err },
		"POST": func() error { _, err := daemonPost(sock, "/retrieve", map[string]interface{}{}); return err },
	} {
		err := call()
		if err == nil || !strings.Contains(err.Error(), "Not trying the shared port") {
			t.Errorf("%s: want the no-TCP refusal, got %v", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), server.TCPOptInEnv) {
			t.Errorf("%s: the refusal must name the opt-in for --http-only daemons: %v", name, err)
		}
	}
}

func TestHealthIsRecognisedWithAQuery(t *testing.T) {
	for path, want := range map[string]bool{"/health": true, "/health?x=1": true, "/retrieve": false, "/healthz": false} {
		if isHealth(path) != want {
			t.Errorf("isHealth(%q) = %v", path, !want)
		}
	}
}
