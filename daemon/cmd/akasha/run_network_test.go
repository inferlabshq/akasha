package main

import (
	"strings"
	"testing"
)

// Three flags, one decision. The refusals matter as much as the acceptances:
// each one is a combination that would otherwise launch with a network posture
// the person did not ask for.
func TestResolveNetworkMode(t *testing.T) {
	cases := []struct {
		noNet          bool
		network, proxy string
		want           networkMode
		wantEndpoint   string
		wantErr        string
	}{
		{false, "", "", netOff, "", ""},
		{false, "off", "", netOff, "", ""},
		{false, "none", "", netNone, "", ""},
		{true, "", "", netNone, "", ""},
		{true, "off", "", netNone, "", ""}, // the flag's own default value does not contradict it
		{true, "none", "", netNone, "", ""},
		{false, "proxy", "127.0.0.1:3128", netProxy, "tcp://127.0.0.1:3128", ""},
		{false, "proxy", "unix:///run/egress.sock", netProxy, "unix:///run/egress.sock", ""},

		{true, "proxy", "127.0.0.1:3128", 0, "", "disagree"},
		{false, "proxy", "", 0, "", "needs --proxy"},
		{false, "proxy", "nonsense", 0, "", "host:port"},
		{false, "off", "127.0.0.1:3128", 0, "", "only reachable under --network proxy"},
		{false, "", "127.0.0.1:3128", 0, "", "only reachable under --network proxy"},
		{false, "none", "127.0.0.1:3128", 0, "", "removes the network entirely"},
		{false, "all", "", 0, "", "want off, none or proxy"},
	}
	for _, c := range cases {
		mode, ep, err := resolveNetworkMode(c.noNet, c.network, c.proxy)
		label := strings.TrimSpace(strings.Join([]string{map[bool]string{true: "--no-network", false: ""}[c.noNet], "--network=" + c.network, "--proxy=" + c.proxy}, " "))
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: want error containing %q, got %v", label, c.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", label, err)
			continue
		}
		if mode != c.want {
			t.Errorf("%s: mode %d, want %d", label, mode, c.want)
		}
		if got := ""; mode == netProxy {
			got = ep.String()
			if got != c.wantEndpoint {
				t.Errorf("%s: endpoint %q, want %q", label, got, c.wantEndpoint)
			}
		}
	}
}
