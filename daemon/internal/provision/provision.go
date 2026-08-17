// Package provision is the single place that turns discovered credentials into
// vaulted, labelled entries via the running daemon. Both `akasha discover` and
// `akasha setup` use it, so the "store fields → build credential map → label
// (+ profile)" plumbing lives here once instead of being duplicated.
package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Client talks to the local daemon. It uses a proxy-free HTTP client so
// localhost traffic is never routed through an interception proxy.
type Client struct {
	base    string
	agentID string
	http    *http.Client
}

// New returns a provisioning client. agentID attributes the audit events
// (e.g. "akasha-discover" or "akasha-setup").
func New(base, agentID string) *Client {
	return &Client{
		base:    base,
		agentID: agentID,
		http: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// NewSocket returns a client bound to one daemon's unix socket.
//
// Prefer this over NewLocal. The loopback port is a machine-wide rendezvous, so
// a TCP client reaches whichever daemon happens to hold it — not necessarily the
// one the caller was configured with. That made --socket and --db silently
// ineffective for provisioning: `akasha discover --db <other>` scanned the HOME
// it was told to and then vaulted the findings into whatever daemon owned 7743,
// which on a machine with two installs is the wrong vault, with no error and a
// success line printed. Addressing the socket names the daemon exactly.
func NewSocket(sockPath, agentID string) *Client {
	return &Client{
		// The authority is ignored by a unix transport but must be well-formed.
		base:    "http://akasha",
		agentID: agentID,
		http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
				},
			},
		},
	}
}

// NewLocal targets the default daemon over the loopback port.
//
// Retained for callers that genuinely have no socket path. Anything that does
// should use NewSocket — see the note there on why the port is ambiguous.
func NewLocal(agentID string) *Client {
	return New("http://127.0.0.1:7743", agentID)
}

func (c *Client) post(path string, payload map[string]interface{}) (map[string]interface{}, error) {
	body, _ := json.Marshal(payload)
	resp, err := c.http.Post(c.base+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: daemon returned %d", path, resp.StatusCode)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	return out, nil
}

// store vaults a single value and returns its token.
func (c *Client) store(content, category string) (string, error) {
	resp, err := c.post("/store", map[string]interface{}{
		"agent_id":  c.agentID,
		"tool_name": "akasha_provision",
		"content":   content,
		"category":  category,
		"risk":      "critical",
		"task":      "Vaulted during credential discovery",
	})
	if err != nil {
		return "", err
	}
	tok, _ := resp["token"].(string)
	if tok == "" {
		return "", fmt.Errorf("daemon returned no token")
	}
	return tok, nil
}

// StoreMap vaults each field value, builds a {field: token} credential map,
// vaults that map, and returns the map token (what a label points at).
func (c *Client) StoreMap(category string, fields map[string]string) (string, error) {
	resolved := map[string]string{}
	for field, value := range fields {
		tok, err := c.store(value, category)
		if err != nil {
			return "", fmt.Errorf("vault %s: %w", field, err)
		}
		resolved[field] = tok
	}
	mapJSON, _ := json.Marshal(resolved)
	return c.store(string(mapJSON), category+"Map")
}

// SetLabel points a human-readable name at a token.
func (c *Client) SetLabel(name, token string) error {
	_, err := c.post("/label/set", map[string]interface{}{"name": name, "token": token})
	return err
}

// SaveProfile records the structured provider/profile row for cloud queries.
func (c *Client) SaveProfile(provider, profile, token string, meta map[string]string) error {
	_, err := c.post("/profile/save", map[string]interface{}{
		"provider": provider, "profile": profile, "token": token, "metadata": meta,
	})
	return err
}

// PurgeOrphans asks the daemon to GC credential chains orphaned by a prior run.
func (c *Client) PurgeOrphans() {
	c.post("/vault/purge", map[string]interface{}{})
}

// ─── Provider vaulting ────────────────────────────────────────────────────

// VaultFinding vaults a template-discovered credential under
// "<provider>:<instance>". It is the only vaulting path: there are no
// compiled-in providers, so every finding — shipped bundle or user template —
// arrives here from a declarative discovery rule.
func (c *Client) VaultFinding(provider, instance string, fields map[string]string, source string) error {
	if len(fields) == 0 {
		return fmt.Errorf("no fields discovered for %s:%s", provider, instance)
	}
	mapTok, err := c.StoreMap(provider+"-credential", fields)
	if err != nil {
		return err
	}
	if err := c.SetLabel(provider+":"+instance, mapTok); err != nil {
		return err
	}
	return c.SaveProfile(provider, instance, mapTok, map[string]string{"source": source})
}
