package vault_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/internal/vault"
)

// vaultAWSProfile mimics what `akasha discover` does for one AWS profile:
// store the underlying field secrets, store a credential-map blob pointing at
// them, then re-point the label (and profile) at the new map token.
func vaultAWSProfile(t *testing.T, v *vault.Vault, profile string) {
	t.Helper()
	const agent = "akasha-discover"

	ak, err := v.Store("AKIA"+profile, "AWSAccessKeyID", "critical", agent, "akasha_discover", 0)
	if err != nil {
		t.Fatalf("store access key: %v", err)
	}
	sk, err := v.Store("secret-"+profile, "AWSSecretKey", "critical", agent, "akasha_discover", 0)
	if err != nil {
		t.Fatalf("store secret key: %v", err)
	}
	mapJSON, _ := json.Marshal(map[string]string{"access_key_id": ak, "secret_access_key": sk})
	mapTok, err := v.Store(string(mapJSON), "AWSCredentialMap", "critical", agent, "akasha_discover", 0)
	if err != nil {
		t.Fatalf("store map: %v", err)
	}
	if err := v.SetLabel("aws:"+profile, mapTok); err != nil {
		t.Fatalf("set label: %v", err)
	}
	if err := v.SaveProfile("aws", profile, mapTok, nil); err != nil {
		t.Fatalf("save profile: %v", err)
	}
}

func total(t *testing.T, v *vault.Vault) int {
	t.Helper()
	n, _, err := v.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	return n
}

// Running discovery repeatedly should not grow the vault once orphans are
// purged: the label/profile resolve to fresh tokens and the stale chains are
// garbage-collected.
func TestPurgeOrphansIdempotentDiscovery(t *testing.T) {
	v := openTemp(t)

	vaultAWSProfile(t, v, "default")
	vaultAWSProfile(t, v, "prod")
	if _, err := v.PurgeOrphans(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	baseline := total(t, v)
	if baseline != 6 { // 2 profiles × (access + secret + map)
		t.Fatalf("expected 6 entries after first run, got %d", baseline)
	}

	// Re-run discovery several times; each run mints fresh chains.
	for i := 0; i < 5; i++ {
		vaultAWSProfile(t, v, "default")
		vaultAWSProfile(t, v, "prod")
		if _, err := v.PurgeOrphans(); err != nil {
			t.Fatalf("purge run %d: %v", i, err)
		}
		if got := total(t, v); got != baseline {
			t.Fatalf("run %d: vault grew to %d (want stable %d)", i, got, baseline)
		}
	}
}

// PurgeOrphans must keep the entries the current label/profile resolve to, and
// those must still decrypt correctly after the stale chain is removed.
func TestPurgeOrphansKeepsLiveCredential(t *testing.T) {
	v := openTemp(t)

	vaultAWSProfile(t, v, "default")
	vaultAWSProfile(t, v, "default") // second run orphans the first chain
	if _, err := v.PurgeOrphans(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	tok, err := v.GetLabel("aws:default")
	if err != nil {
		t.Fatalf("get label: %v", err)
	}
	plain, err := v.Retrieve(tok, "akasha_discover")
	if err != nil {
		t.Fatalf("retrieve map (should survive purge): %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(plain), &m); err != nil {
		t.Fatalf("map not valid JSON: %v", err)
	}
	for field, ref := range m {
		if _, err := v.Retrieve(ref, "akasha_discover"); err != nil {
			t.Fatalf("underlying token for %q was purged: %v", field, err)
		}
	}

	if got := total(t, v); got != 3 {
		t.Fatalf("expected 3 live entries, got %d", got)
	}
}

// CountNonDiscovered counts only live secrets an agent wrapped — not discovery
// credentials and not expired entries.
func TestCountNonDiscovered(t *testing.T) {
	v := openTemp(t)

	// Discovery-created entries — must NOT count.
	vaultAWSProfile(t, v, "default")
	// Two agent-wrapped secrets — must count.
	if _, err := v.Store("sk-1", "APIKey", "critical", "claude-code", "wrap", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Store("sk-2", "APIKey", "critical", "cursor", "wrap", 0); err != nil {
		t.Fatal(err)
	}
	// An already-expired agent secret — must NOT count.
	if _, err := v.Store("sk-old", "APIKey", "critical", "cursor", "wrap", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // ensure the nanosecond TTL has elapsed

	n, err := v.CountNonDiscovered()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 non-discovered live secrets, got %d", n)
	}
}

// Secrets stored by real agents (not the discovery flows) are never touched by
// PurgeOrphans, even when nothing references them.
func TestPurgeOrphansSparesAgentSecrets(t *testing.T) {
	v := openTemp(t)

	tok, err := v.Store("sk-live-123", "APIKey", "critical", "some-real-agent", "wrap", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := v.PurgeOrphans(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := v.Retrieve(tok, "wrap"); err != nil {
		t.Fatalf("agent secret was wrongly purged: %v", err)
	}
}
