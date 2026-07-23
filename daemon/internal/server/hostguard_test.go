package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The TCP listener's hostGuard is the DNS-rebinding / cross-origin defence: a
// loopback Host and no foreign Origin pass; an attacker domain (rebinding) or a
// cross-origin browser request is refused.
func TestHostGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := hostGuard(ok)

	cases := []struct {
		name   string
		host   string
		origin string
		want   int
	}{
		{"loopback ip", "127.0.0.1:7743", "", http.StatusOK},
		{"loopback ip no port", "127.0.0.1", "", http.StatusOK},
		{"localhost", "localhost:7743", "", http.StatusOK},
		{"ipv6 loopback", "[::1]:7743", "", http.StatusOK},
		{"127/8 loopback", "127.9.9.9:7743", "", http.StatusOK},
		{"rebinding domain", "attacker.example:7743", "", http.StatusForbidden},
		{"public ip", "203.0.113.5:7743", "", http.StatusForbidden},
		{"loopback host, cross-origin", "127.0.0.1:7743", "http://attacker.example", http.StatusForbidden},
		{"loopback host, loopback origin", "127.0.0.1:7743", "http://localhost:7743", http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/retrieve", nil)
		req.Host = c.host
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: Host=%q Origin=%q → %d, want %d", c.name, c.host, c.origin, rec.Code, c.want)
		}
	}
}
