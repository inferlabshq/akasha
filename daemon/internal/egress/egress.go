// Package egress is the plumbing for `akasha run --network proxy`: one route
// off the machine, chosen by the operator, and nothing else.
//
// The sandbox removes IP networking from the run (a network namespace on Linux,
// an IP deny on macOS). Pathname unix sockets survive both, so a unix socket in
// the run directory is the only thing that can carry bytes out. Tools do not
// speak proxy-over-unix, though — HTTPS_PROXY wants host:port — so two small
// pipes turn that socket back into an ordinary loopback proxy address:
//
//	inside the sandbox            run dir                outside
//	tool ── 127.0.0.1:PORT ── relay ── egress.sock ── forwarder ── operator's proxy
//
// The relay runs inside as the child's parent (it has to: inside a network
// namespace, 127.0.0.1 is a different loopback). The forwarder runs in the
// supervisor and dials whatever the operator named — a TCP proxy on loopback,
// a corporate proxy on the LAN, or a unix socket.
//
// akasha does not build a firewall, and must not. It makes the operator's
// proxy the only reachable thing; the proxy decides what is allowed. That
// includes loopback: a CONNECT to 127.0.0.1:27017 sent to the proxy is the
// proxy's decision, not the sandbox's, and the banner says so.
//
// Both pipes copy bytes. Neither parses HTTP, so neither can be confused by
// it, and a CONNECT proxy sees hostnames without any TLS interception.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Endpoint is where the operator's proxy listens.
type Endpoint struct {
	Network string // "tcp" or "unix"
	Addr    string // host:port, or an absolute socket path
}

func (e Endpoint) String() string {
	if e.Network == "unix" {
		return "unix://" + e.Addr
	}
	return "tcp://" + e.Addr
}

// ParseEndpoint accepts the spellings a person would type for --proxy:
//
//	127.0.0.1:3128          a TCP proxy (the common case)
//	tcp://proxy.corp:3128   the same, explicit
//	http://127.0.0.1:3128   what HTTPS_PROXY already holds; scheme is
//	                        accepted and ignored, the proxy protocol is the
//	                        tool's business
//	unix:///run/egress.sock a proxy listening on a unix socket (Envoy)
//
// It refuses anything without a port, a relative socket path, and a URL with
// a path or userinfo, because each of those is a typo that would otherwise
// become a silent misroute.
func ParseEndpoint(s string) (Endpoint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Endpoint{}, errors.New("--proxy is empty; name the proxy, e.g. --proxy 127.0.0.1:3128")
	}
	if !strings.Contains(s, "://") {
		return tcpEndpoint(s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("--proxy %q: %v", s, err)
	}
	if u.User != nil {
		return Endpoint{}, fmt.Errorf("--proxy %q: credentials in the proxy address are not supported; configure the proxy to trust this host, or put them in the tool's own proxy setting", s)
	}
	switch u.Scheme {
	case "unix":
		p := u.Path
		if u.Host != "" {
			// unix://relative/path parses the first segment as a host.
			return Endpoint{}, fmt.Errorf("--proxy %q: a unix socket path must be absolute (unix:///path/to.sock, three slashes)", s)
		}
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return Endpoint{}, fmt.Errorf("--proxy %q: a unix socket path must be absolute and clean", s)
		}
		return Endpoint{Network: "unix", Addr: p}, nil
	case "tcp", "http", "https":
		if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
			return Endpoint{}, fmt.Errorf("--proxy %q: a proxy address is host:port with no path", s)
		}
		return tcpEndpoint(u.Host)
	default:
		return Endpoint{}, fmt.Errorf("--proxy %q: scheme %q is not one of tcp://, http://, unix://", s, u.Scheme)
	}
}

func tcpEndpoint(hostport string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" {
		return Endpoint{}, fmt.Errorf("--proxy %q: want host:port (e.g. 127.0.0.1:3128)", hostport)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Endpoint{}, fmt.Errorf("--proxy %q: port %q is not a number in 1..65535", hostport, port)
	}
	return Endpoint{Network: "tcp", Addr: net.JoinHostPort(host, port)}, nil
}

// Dial connects to the endpoint, bounded so a dead proxy fails a request
// instead of hanging it.
func (e Endpoint) Dial() (net.Conn, error) {
	return net.DialTimeout(e.Network, e.Addr, 5*time.Second)
}

// Preflight proves the proxy answers before the run starts. A run whose only
// route out is dead should refuse to launch with the proxy's name in the
// message, not launch and then fail its first request with a generic
// "connection refused" from inside a namespace nobody can see.
func (e Endpoint) Preflight() error {
	c, err := e.Dial()
	if err != nil {
		return fmt.Errorf("the proxy at %s is not reachable from here (%v).\n"+
			"  --network proxy makes that proxy the run's only route out, so it has to be\n"+
			"  listening before the run starts.", e, unwrapDial(err))
	}
	c.Close()
	return nil
}

func unwrapDial(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err
	}
	return err
}

// FreeLoopbackPort asks the kernel for a port nothing on this host is using.
//
// Inside a Linux network namespace every port is free, but the same number is
// used on macOS where loopback is shared with the host, and one code path for
// both is worth the small bind-then-release race on the shared one.
func FreeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ProxyEnv is what the child sees. Both cases of each name, because the tools
// disagree: curl reads the lowercase ones, Go and Node the upper. NO_PROXY
// keeps well-behaved tools from routing loopback through the proxy; it is a
// courtesy to the tool, not a control — the proxy is what refuses loopback, if
// anything does.
func ProxyEnv(port int) map[string]string {
	addr := "http://127.0.0.1:" + strconv.Itoa(port)
	return map[string]string{
		"HTTP_PROXY": addr, "http_proxy": addr,
		"HTTPS_PROXY": addr, "https_proxy": addr,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
	}
}

// Serve accepts on ln and pipes each connection to a fresh dial(). It returns
// when ctx ends or the listener closes. onError is called once per failed dial
// and once for the first accept error; it never blocks the loop.
func Serve(ctx context.Context, ln net.Listener, dial func() (net.Conn, error), onError func(error)) {
	if onError == nil {
		onError = func(error) {}
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				onError(fmt.Errorf("accept: %w", err))
			}
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			up, err := dial()
			if err != nil {
				onError(err)
				return
			}
			defer up.Close()
			pipe(c, up)
		}()
	}
	wg.Wait()
}

// pipe copies both ways and returns when either side is done. Half-close is
// honoured where the transport supports it so an HTTP proxy that closes its
// write side after a response does not strand the tool's read.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// ListenUnix opens the forwarder's socket in the run directory, owner-only.
//
// Opened O_EXCL in effect: a socket file already at that path is a bug or a
// squat, and either way the run must not adopt it. The directory is 0700 and
// owned by the caller, so the socket's own mode is belt and braces.
func ListenUnix(path string) (net.Listener, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("egress: %s already exists", path)
	}
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// OnceReporter turns a stream of pipe errors into one line per distinct
// message, so an agent hammering a dead proxy does not flood the terminal.
func OnceReporter(w io.Writer, prefix string) func(error) {
	var mu sync.Mutex
	seen := map[string]bool{}
	return func(err error) {
		if err == nil {
			return
		}
		msg := err.Error()
		mu.Lock()
		defer mu.Unlock()
		if seen[msg] {
			return
		}
		seen[msg] = true
		fmt.Fprintf(w, "%s%s\n", prefix, msg)
	}
}

// RunRelay is the inside half. It listens on listen (127.0.0.1:PORT), pipes
// every connection to the unix socket at upstream, runs argv as its child with
// the caller's stdio, forwards signals, and returns the child's exit code.
//
// The listener is opened BEFORE the child starts, so a tool's first request
// cannot race it, and a port that cannot be bound is a launch error with the
// port in it rather than a proxy error later.
func RunRelay(listen, upstream string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 2, errors.New("relay: no command")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return 2, fmt.Errorf("relay: cannot listen on %s: %w", listen, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up := Endpoint{Network: "unix", Addr: upstream}
	go Serve(ctx, ln, up.Dial, OnceReporter(stderr, "akasha run: proxy relay: "))

	child := exec.Command(argv[0], argv[1:]...)
	child.Stdin, child.Stdout, child.Stderr = stdin, stdout, stderr
	if err := child.Start(); err != nil {
		return 2, err
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigc {
			if child.Process != nil {
				child.Process.Signal(s)
			}
		}
	}()
	werr := child.Wait()
	signal.Stop(sigc)
	close(sigc)
	var exitErr *exec.ExitError
	if errors.As(werr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if werr != nil {
		return 2, werr
	}
	return 0, nil
}
