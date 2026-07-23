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
	"strings"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/server"
	"golang.org/x/term"
)

// agentKeyHeader returns the X-Akasha-Key header line (raw-HTTP form) when
// the session environment carries an agent key. Setup injects
// AKASHA_AGENT_KEY into agent harness sessions, so CLI calls made from inside
// one (notably `akasha helper`) authenticate as that agent instead of relying
// on the advisory agent_id in the body.
func agentKeyHeader() string {
	if k := os.Getenv("AKASHA_AGENT_KEY"); k != "" {
		return "X-Akasha-Key: " + k + "\r\n"
	}
	return ""
}

func daemonPost(sock, path string, payload map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	var respBody []byte

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		// HTTP fallback.
		req, _ := http.NewRequest("POST",
			fmt.Sprintf("http://127.0.0.1:%d%s", server.HTTPPort, path),
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if k := os.Getenv("AKASHA_AGENT_KEY"); k != "" {
			req.Header.Set("X-Akasha-Key", k)
		}
		resp, err2 := http.DefaultClient.Do(req)
		if err2 != nil {
			return nil, fmt.Errorf("daemon not reachable (is `akasha start` running?): %w", err)
		}
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(resp.Body)
	} else {
		defer conn.Close()
		req := fmt.Sprintf("POST %s HTTP/1.0\r\nHost: localhost\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", path, agentKeyHeader(), len(body))
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
		raw := string(buf)
		if idx := indexOf(raw, "\r\n\r\n"); idx >= 0 {
			respBody = []byte(raw[idx+4:])
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("bad response from daemon: %s", respBody)
	}
	return result, nil
}

func daemonGet(sock, path string) (string, error) {
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		// Fallback to HTTP.
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", server.HTTPPort, path), nil)
		if k := os.Getenv("AKASHA_AGENT_KEY"); k != "" {
			req.Header.Set("X-Akasha-Key", k)
		}
		resp, err2 := http.DefaultClient.Do(req)
		if err2 != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	defer conn.Close()

	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: localhost\r\n%s\r\n", path, agentKeyHeader())
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
	// Strip HTTP response headers.
	body := string(buf)
	if idx := indexOf(body, "\r\n\r\n"); idx >= 0 {
		body = body[idx+4:]
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
