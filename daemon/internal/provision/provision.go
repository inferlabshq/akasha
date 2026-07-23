// Package provision is the single place that turns discovered credentials into
// vaulted, labelled entries via the running daemon. Both `akasha discover` and
// `akasha setup` use it, so the "store fields → build credential map → label
// (+ profile)" plumbing lives here once instead of being duplicated.
package provision

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/discover"
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

// NewLocal targets the default daemon address.
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
// "<provider>:<instance>". This is the generic path for user provider
// templates and discovery rules — the typed VaultAWS/VaultSSH/VaultGit
// methods stay for the hand-tuned Go scanners.
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

// VaultAWS vaults an AWS credential set under label "aws:<profile>" and records
// a structured profile row with source metadata.
func (c *Client) VaultAWS(cred discover.AWSCredential) error {
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return fmt.Errorf("incomplete AWS credential for profile %q", cred.Profile)
	}
	fields := map[string]string{
		"access_key_id":     cred.AccessKeyID,
		"secret_access_key": cred.SecretAccessKey,
	}
	if cred.SessionToken != "" {
		fields["session_token"] = cred.SessionToken
	}
	mapTok, err := c.StoreMap("AWSCredential", fields)
	if err != nil {
		return err
	}
	if err := c.SetLabel("aws:"+cred.Profile, mapTok); err != nil {
		return err
	}
	meta := map[string]string{"source": cred.FormatSource()}
	if cred.Source == discover.SourceAWSCredentialsFile || cred.Source == discover.SourceAWSConfigFile {
		meta["config_path"] = cred.SourcePath
	}
	return c.SaveProfile("aws", cred.Profile, mapTok, meta)
}

// VaultSSH reads the private key file and vaults it under "ssh:<profile>".
func (c *Client) VaultSSH(cred discover.SSHCredential) error {
	data, err := os.ReadFile(cred.KeyPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cred.KeyPath, err)
	}
	mapTok, err := c.StoreMap("SSHPrivateKey", map[string]string{"private_key": string(data)})
	if err != nil {
		return err
	}
	return c.SetLabel("ssh:"+cred.Profile, mapTok)
}

// VaultGit vaults a git token under "git:<profile>".
func (c *Client) VaultGit(cred discover.GitCredential) error {
	mapTok, err := c.StoreMap("GitToken", map[string]string{"token": cred.Token})
	if err != nil {
		return err
	}
	return c.SetLabel("git:"+cred.Profile, mapTok)
}
