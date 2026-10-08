package egress

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseEndpoint(t *testing.T) {
	good := map[string]Endpoint{
		"127.0.0.1:3128":          {"tcp", "127.0.0.1:3128"},
		"tcp://proxy.corp:3128":   {"tcp", "proxy.corp:3128"},
		"http://127.0.0.1:3128":   {"tcp", "127.0.0.1:3128"},
		"http://127.0.0.1:3128/":  {"tcp", "127.0.0.1:3128"},
		"[::1]:3128":              {"tcp", "[::1]:3128"},
		"unix:///run/egress.sock": {"unix", "/run/egress.sock"},
		" 127.0.0.1:8080 ":        {"tcp", "127.0.0.1:8080"},
	}
	for in, want := range good {
		got, err := ParseEndpoint(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %+v, want %+v", in, got, want)
		}
	}

	// Each of these is a typo that would otherwise become a silent misroute.
	bad := []string{
		"", "3128", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:abc",
		"unix://egress.sock", "unix://run/egress.sock", "unix:///run/../etc/x.sock",
		"http://user:pw@127.0.0.1:3128", "http://127.0.0.1:3128/path", "socks5://127.0.0.1:1080",
	}
	for _, in := range bad {
		if got, err := ParseEndpoint(in); err == nil {
			t.Errorf("%q: accepted as %+v, want an error", in, got)
		}
	}
}

// The pipe has to carry bytes both ways and finish when the upstream closes,
// which is what an HTTP proxy does after a response.
func TestServePipesToUpstream(t *testing.T) {
	up, err := net.Listen("unix", filepath.Join(t.TempDir(), "up.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				c.Write(append([]byte("echo:"), buf[:n]...))
			}()
		}
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errs lockedBuffer
	go Serve(ctx, front, Endpoint{"unix", up.Addr().String()}.Dial, OnceReporter(&errs, ""))

	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("CONNECT example.com:443"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "echo:CONNECT example.com:443" {
		t.Fatalf("got %q", got)
	}
	if errs.Len() != 0 {
		t.Fatalf("unexpected pipe errors: %s", errs.String())
	}
}

// A dead upstream is reported once, not once per connection, and the pipe
// keeps serving.
func TestServeReportsDeadUpstreamOnce(t *testing.T) {
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errs lockedBuffer
	dead := Endpoint{"unix", filepath.Join(t.TempDir(), "nobody.sock")}
	go Serve(ctx, front, dead.Dial, OnceReporter(&errs, "relay: "))

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(make([]byte, 1)) // EOF once the failed dial closes us
		c.Close()
	}
	time.Sleep(50 * time.Millisecond)
	if n := strings.Count(errs.String(), "relay: "); n != 1 {
		t.Fatalf("want exactly one report, got %d:\n%s", n, errs.String())
	}
}

func TestPreflightNamesTheProxy(t *testing.T) {
	dead := Endpoint{"tcp", "127.0.0.1:1"}
	err := dead.Preflight()
	if err == nil {
		t.Fatal("a closed port passed preflight")
	}
	if !strings.Contains(err.Error(), "tcp://127.0.0.1:1") {
		t.Fatalf("error does not name the proxy: %v", err)
	}
	live, _ := net.Listen("tcp", "127.0.0.1:0")
	defer live.Close()
	if err := (Endpoint{"tcp", live.Addr().String()}).Preflight(); err != nil {
		t.Fatalf("a listening port failed preflight: %v", err)
	}
}

func TestProxyEnvBothCases(t *testing.T) {
	env := ProxyEnv(4242)
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if env[k] != "http://127.0.0.1:4242" {
			t.Errorf("%s = %q", k, env[k])
		}
	}
	if !strings.Contains(env["NO_PROXY"], "127.0.0.1") || env["no_proxy"] != env["NO_PROXY"] {
		t.Errorf("NO_PROXY = %q / %q", env["NO_PROXY"], env["no_proxy"])
	}
}

// The relay is the child's parent inside the sandbox, so the child's exit code
// has to come back through it unchanged — otherwise every agent exit looks
// like success.
func TestRunRelayPropagatesExitCode(t *testing.T) {
	up := filepath.Join(t.TempDir(), "up.sock")
	code, err := RunRelay("127.0.0.1:0", up, []string{"/bin/sh", "-c", "exit 7"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	if _, err := RunRelay("127.0.0.1:0", up, nil, nil, nil, nil); err == nil {
		t.Fatal("no command accepted")
	}
	// A port that cannot be bound is a launch error, not a proxy error later.
	taken, _ := net.Listen("tcp", "127.0.0.1:0")
	defer taken.Close()
	if _, err := RunRelay(taken.Addr().String(), up, []string{"/bin/true"}, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "cannot listen") {
		t.Fatalf("a taken port did not refuse the launch: %v", err)
	}
}

// lockedBuffer is what the relay's error writer must be in a test: Serve
// reports from its own goroutines while the test reads, and a bare
// bytes.Buffer made every -race run fail (CI on main since alpha.6). The
// reporter's mutex orders its writes, not the test's reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuffer) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Len()
}
