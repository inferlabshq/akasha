package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/clikey"
	"github.com/inferlabshq/akasha/daemon/internal/server"
	"golang.org/x/term"
)

// callerKey returns the key this invocation authenticates with.
//
// Precedence is deliberate and must not be reordered:
//
//  1. AKASHA_AGENT_KEY from the environment. Setup injects it into agent
//     harness sessions, so a CLI call made from inside one (notably
//     `akasha helper`) authenticates as THAT AGENT and is held to the agent's
//     policy scope.
//  2. The local CLI key, provisioned by the daemon at startup.
//
// The agent key wins because falling back to the CLI key inside an agent
// session would be privilege escalation with extra steps: an agent could shell
// out to `akasha` and be served as the human. An agent session is therefore
// never silently upgraded — if its key is revoked, the CLI key on disk must not
// rescue it. That is what the AKASHA_AGENT_ID branch below is for: a session
// carrying an agent identity but no key is an agent session that DROPPED its
// key, which is exactly the move `agent revoke` has to survive.
//
// Be clear about what that branch is worth. It reads the environment, and the
// environment belongs to the caller, so `env -u AKASHA_AGENT_ID` walks past it.
// It is drift protection: it stops the accidental and the casual escalation,
// and it stops this CLI from PERFORMING one on an agent's behalf. It is not the
// enforcement boundary. The enforcement boundary is the daemon, which refuses
// unauthenticated callers outright (see server.auth) — and even that stops at
// the same-uid ceiling, because cli.key is readable by any process running as
// this user. See internal/clikey and docs/design/same-user-identity.md.
func callerKey() (string, error) {
	if k := os.Getenv("AKASHA_AGENT_KEY"); k != "" {
		return k, nil
	}
	if id := os.Getenv("AKASHA_AGENT_ID"); id != "" {
		return "", fmt.Errorf("this session is agent %q (AKASHA_AGENT_ID is set) but carries no AKASHA_AGENT_KEY, "+
			"so it has no identity to present.\n"+
			"  Akasha will NOT fall back to the local CLI's key here: an agent that dropped its key must not be\n"+
			"  served as the human. If the key was revoked, that revocation is the answer — not a workaround.\n"+
			"  If you are the human, run this from a plain terminal instead of inside the agent session.", id)
	}
	return clikey.Load(clikey.Path(dbPath)), nil
}

// agentKeyHeader renders a key as the X-Akasha-Key header line for the
// hand-rolled HTTP/1.0 exchange used over the unix socket.
func agentKeyHeader(key string) string {
	if key == "" {
		return ""
	}
	return "X-Akasha-Key: " + key + "\r\n"
}

func daemonPost(sock, path string, payload map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	key, err := callerKey()
	if err != nil {
		return nil, err
	}

	var respBody []byte

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		// A POST is a WRITE, so redirecting it to another daemon is the worse
		// half of this bug: it mutates the wrong vault. See targetedExplicitly.
		if targetedExplicitly() {
			return nil, noFallbackErr(sock, err)
		}
		// HTTP fallback — the `--http-only` daemon has no socket to dial.
		req, _ := http.NewRequest("POST",
			fmt.Sprintf("http://127.0.0.1:%d%s", server.HTTPPort, path),
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("X-Akasha-Key", key)
		}
		resp, err2 := http.DefaultClient.Do(req)
		if err2 != nil {
			return nil, bothPathsFailedErr(sock, err, err2)
		}
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(resp.Body)
		if err := statusError(resp.StatusCode, string(respBody)); err != nil {
			return nil, err
		}
	} else {
		defer conn.Close()
		req := fmt.Sprintf("POST %s HTTP/1.0\r\nHost: localhost\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", path, agentKeyHeader(key), len(body))
		conn.Write([]byte(req))
		conn.Write(body)
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		code, body := splitRawResponse(string(buf))
		if err := statusError(code, body); err != nil {
			return nil, err
		}
		respBody = []byte(body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("bad response from daemon: %s", respBody)
	}
	return result, nil
}

// splitRawResponse parses the hand-rolled HTTP/1.0 exchange used over the unix
// socket into (status code, body). Both socket paths used to discard the status
// line entirely and hand the body back as if it were a success, so an error
// response reached the caller disguised as data: `akasha list` reported the
// daemon's clear "agent key has been revoked — repair it with ..." message as
// "unexpected response: ...", because the CLI tried to JSON-decode the prose.
// The daemon's remediation text is the most useful thing it can say; it should
// arrive as the error, not as a parse failure.
func splitRawResponse(raw string) (int, string) {
	code := 0
	if line, _, ok := strings.Cut(raw, "\r\n"); ok {
		// "HTTP/1.0 403 Forbidden" → 403
		if parts := strings.Fields(line); len(parts) >= 2 {
			code, _ = strconv.Atoi(parts[1])
		}
	}
	body := raw
	if idx := indexOf(raw, "\r\n\r\n"); idx >= 0 {
		body = raw[idx+4:]
	}
	return code, body
}

// statusError turns a non-2xx daemon response into an error carrying the
// daemon's own message. A zero code means the status line was unparseable,
// which is treated as success so a malformed-but-decodable response still
// works — the body itself will fail to parse if it is genuinely broken.
func statusError(code int, body string) error {
	if code < 400 {
		return nil
	}
	msg := strings.TrimSpace(body)
	if msg == "" {
		return fmt.Errorf("daemon returned HTTP %d", code)
	}
	return fmt.Errorf("%s", msg)
}

// targetedExplicitly reports whether this invocation was pinned to a particular
// daemon or vault with --socket / --db.
//
// It gates the HTTP fallback below. The fallback exists for `akasha start
// --http-only`, where there is no unix socket to reach — but it dials a FIXED
// shared port, so when the named socket is unreachable it silently reaches
// whatever daemon owns that port instead. That daemon may be serving a
// different --db, i.e. a different vault.
//
// This is not hypothetical: a command aimed at a scratch daemon whose socket
// had failed to bind wrote into the real vault, because the fallback quietly
// redirected it. If you named a target, an unreachable target is an error.
func targetedExplicitly() bool {
	f := rootCmd.PersistentFlags()
	return f.Changed("socket") || f.Changed("db")
}

// noFallbackErr explains why a named-but-unreachable socket is fatal.
// bothPathsFailedErr reports what BOTH transports said.
//
// The client dials the unix socket and, if that fails, falls back to the shared
// HTTP port. This used to return the SOCKET's error after the HTTP attempt had
// failed — so it described a failure from two steps ago and threw away the one
// that had just happened. daemonGet did not even do that: it returned the dial
// error bare and let each caller guess at a sentence for it.
//
// It also asserted a cause. "is `akasha start` running?" is the wrong question
// whenever the daemon IS running and something else stopped the client reaching
// it: a --socket or --db naming a different vault, a stale socket file left by a
// killed daemon, a socket path over the kernel's length limit, or a daemon
// listening on another HTTP port. Guessing one cause out of five and printing it
// as though it were a diagnosis sends people to restart a daemon that is already
// up, which is an hour gone.
//
// So it states what was tried and what each attempt said, and offers the causes
// in the order they are worth checking — without claiming to know which it is.
func bothPathsFailedErr(sock string, dialErr, httpErr error) error {
	return fmt.Errorf("could not reach the daemon on either transport:\n"+
		"    unix socket %s\n      %v\n"+
		"    http 127.0.0.1:%d\n      %v\n"+
		"  If it is not running, `akasha start`. If it IS running, then it is not the one\n"+
		"  this command is addressing: check --socket/--db, look for a stale socket file\n"+
		"  from a killed daemon, and note that a socket path must stay under %d bytes.",
		sock, dialErr, server.HTTPPort, httpErr, server.MaxUnixSocketPath)
}

func noFallbackErr(sock string, dialErr error) error {
	return fmt.Errorf("daemon socket %s is not reachable: %v\n"+
		"  Not falling back to the shared HTTP port (127.0.0.1:%d), because you named a\n"+
		"  specific --socket/--db and that port may belong to a DIFFERENT daemon serving a\n"+
		"  different vault.\n"+
		"  Check the daemon is running and that its socket path is under %d bytes.",
		sock, dialErr, server.HTTPPort, server.MaxUnixSocketPath)
}

func daemonGet(sock, path string) (string, error) {
	key, err := callerKey()
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		if targetedExplicitly() {
			return "", noFallbackErr(sock, err)
		}
		// Fallback to HTTP — the `--http-only` daemon has no socket to dial.
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", server.HTTPPort, path), nil)
		if key != "" {
			req.Header.Set("X-Akasha-Key", key)
		}
		resp, err2 := http.DefaultClient.Do(req)
		if err2 != nil {
			return "", bothPathsFailedErr(sock, err, err2)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if err := statusError(resp.StatusCode, string(b)); err != nil {
			return "", err
		}
		return string(b), nil
	}
	defer conn.Close()

	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: localhost\r\n%s\r\n", path, agentKeyHeader(key))
	conn.Write([]byte(req))

	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	code, body := splitRawResponse(string(buf))
	if err := statusError(code, body); err != nil {
		return "", err
	}
	return body, nil
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

type bytesReader struct {
	b   []byte
	pos int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

// readPassphrase reads a line from stdin without echo where possible.
func readPassphrase() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return b, err
	}
	// Non-interactive (piped) — read a plain line.
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	return []byte(strings.TrimSpace(line)), err
}
