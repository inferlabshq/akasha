package vault_test

import (
	"sync"
	"testing"
	"time"
)

// A single-use grant must not be redeemable twice, even when many agents race to
// redeem it at once (finding #4).
func TestRedeemGrantSingleUseUnderRace(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("card", "CreditCard", "critical", "a", "charge", 0)
	gid, err := v.CreateGrant(tok, "a", "b", "charge", "task", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if got, err := v.RedeemGrant(gid, "b", "charge"); err == nil {
				mu.Lock()
				wins++
				if got != tok {
					t.Errorf("redemption returned %q, want grant token %q", got, tok)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("single-use grant redeemed %d times, want exactly 1", wins)
	}
}

// ─── Agent keys ───────────────────────────────────────────────────────────

func TestAgentKeyLifecycle(t *testing.T) {
	v := openTemp(t)

	keyID, plaintext, err := v.CreateAgentKey("support-bot")
	if err != nil {
		t.Fatal(err)
	}
	if keyID == "" || plaintext == "" {
		t.Fatal("empty key material")
	}

	// Verify valid key → agent id.
	agentID, err := v.VerifyAgentKey(plaintext)
	if err != nil || agentID != "support-bot" {
		t.Fatalf("verify: id=%q err=%v", agentID, err)
	}

	// Invalid key rejected.
	if _, err := v.VerifyAgentKey("agt_nope"); err == nil {
		t.Fatal("expected error for invalid key")
	}

	// List shows it.
	keys, err := v.ListAgentKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].AgentID != "support-bot" || keys[0].Revoked {
		t.Fatalf("list: %+v", keys)
	}
	if keys[0].LastUsed == nil {
		t.Fatal("LastUsed should be set after a verify")
	}

	// Revoke → verify now fails.
	if err := v.RevokeAgentKey(keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyAgentKey(plaintext); err == nil {
		t.Fatal("revoked key should fail verification")
	}

	// Revoke unknown → error.
	if err := v.RevokeAgentKey("agt_missing"); err == nil {
		t.Fatal("expected error revoking unknown key")
	}

	// A long agent id exercises the key-id truncation branch.
	kid2, _, err := v.CreateAgentKey("a-very-long-agent-identifier-beyond-sixteen-chars")
	if err != nil || len(kid2) == 0 {
		t.Fatalf("long agent id: %v", err)
	}
}

// PurgeOrphans full sweep: collects roots from labels + profiles + grants,
// follows credential-map indirection, tolerates a non-map root, and deletes a
// genuine discovery-created orphan while keeping everything reachable.
func TestPurgeOrphansFullSweep(t *testing.T) {
	v := openTemp(t)

	akTok, _ := v.Store("AKIA", "AWSAccessKeyID", "critical", "akasha-discover", "t", 0)
	mapJSON := `{"access_key_id":"` + akTok + `"}`
	mapTok, _ := v.Store(mapJSON, "AWSCredentialMap", "critical", "akasha-discover", "t", 0)
	v.SetLabel("aws:default", mapTok)              // label root → follows map → akTok
	v.SaveProfile("aws", "default", mapTok, nil)   // profile root
	v.CreateGrant(akTok, "a", "b", "t", "task", 0) // grant root

	// Label pointing at a plain (non-JSON-map) secret → exercises the
	// "root isn't a credential map" path in reachableTokens.
	plain, _ := v.Store("just-a-string", "X", "high", "akasha-discover", "t", 0)
	v.SetLabel("plain:x", plain)

	// A genuine orphan: created by discovery, referenced by nothing.
	orphan, _ := v.Store("orphan", "X", "high", "akasha-discover", "t", 0)

	n, err := v.PurgeOrphans()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least the orphan purged, got %d", n)
	}
	// Orphan gone, referenced entries kept.
	if _, err := v.Retrieve(orphan, "t"); err == nil {
		t.Fatal("orphan should have been purged")
	}
	if _, err := v.Retrieve(akTok, "t"); err != nil {
		t.Fatal("referenced access key must be kept")
	}
	if _, err := v.Retrieve(plain, "t"); err != nil {
		t.Fatal("labelled plain secret must be kept")
	}
}

// ─── Profiles ─────────────────────────────────────────────────────────────

func TestProfileLifecycle(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("blob", "AWSCredentialMap", "critical", "a", "t", 0)

	// Save with no metadata (nil branch), then overwrite (ON CONFLICT) with
	// metadata — exercises both the metadata-marshal and conflict paths.
	if err := v.SaveProfile("aws", "default", tok, nil); err != nil {
		t.Fatal(err)
	}
	if err := v.SaveProfile("aws", "default", tok, map[string]string{"region": "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	// A second provider/profile.
	if err := v.SaveProfile("gcp", "proj", tok, map[string]string{"project_id": "p1"}); err != nil {
		t.Fatal(err)
	}

	got, err := v.GetProfile("aws", "default")
	if err != nil || got.Token != tok {
		t.Fatalf("get profile: %+v err=%v", got, err)
	}

	if _, err := v.GetProfile("aws", "ghost"); err == nil {
		t.Fatal("expected error for unknown profile")
	}

	all, err := v.ListProfiles("")
	if err != nil || len(all) != 2 {
		t.Fatalf("list all: %d %v", len(all), err)
	}
	awsOnly, err := v.ListProfiles("aws")
	if err != nil || len(awsOnly) != 1 || awsOnly[0].Metadata["region"] != "us-east-1" {
		t.Fatalf("list aws: %+v", awsOnly)
	}
}

// ─── Labels ───────────────────────────────────────────────────────────────

func TestLabelLifecycle(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("v", "APIKey", "high", "a", "t", 0)

	if err := v.SetLabel("aws:default", tok); err != nil {
		t.Fatal(err)
	}
	// Overwrite same label.
	if err := v.SetLabel("aws:default", tok); err != nil {
		t.Fatal(err)
	}
	if err := v.SetLabel("ssh:gitlab", tok); err != nil {
		t.Fatal(err)
	}

	got, err := v.GetLabel("aws:default")
	if err != nil || got != tok {
		t.Fatalf("get label: %q %v", got, err)
	}
	if _, err := v.GetLabel("nope"); err == nil {
		t.Fatal("expected error for unknown label")
	}

	names, err := v.ListLabels("aws:")
	if err != nil || len(names) != 1 || names[0] != "aws:default" {
		t.Fatalf("list labels: %v", names)
	}
	all, _ := v.ListLabels("")
	if len(all) != 2 {
		t.Fatalf("list all labels: %v", all)
	}
}

// ─── Grant inspect + redeem edge cases ────────────────────────────────────

func TestGrantInspectAndEdgeCases(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("card", "CreditCard", "critical", "a", "charge", 0)

	gid, err := v.CreateGrant(tok, "a", "b", "charge", "task", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	g, err := v.InspectGrant(gid)
	if err != nil || g.Token != tok || g.GranteeAgent != "b" {
		t.Fatalf("inspect grant: %+v err=%v", g, err)
	}
	if _, err := v.InspectGrant("grt://missing"); err == nil {
		t.Fatal("expected error for unknown grant")
	}

	// invalid grant format
	if _, err := v.RedeemGrant("not-a-grant", "b", "charge"); err == nil {
		t.Fatal("expected invalid-format error")
	}
	// unknown grant
	if _, err := v.RedeemGrant("grt://missing", "b", "charge"); err == nil {
		t.Fatal("expected not-found error")
	}
	// wrong grantee
	if _, err := v.RedeemGrant(gid, "c", "charge"); err == nil {
		t.Fatal("expected wrong-grantee error")
	}
	// wrong tool
	if _, err := v.RedeemGrant(gid, "b", "send_email"); err == nil {
		t.Fatal("expected wrong-tool error")
	}
	// correct → ok, then single-use
	if _, err := v.RedeemGrant(gid, "b", "charge"); err != nil {
		t.Fatalf("valid redeem: %v", err)
	}
	if _, err := v.RedeemGrant(gid, "b", "charge"); err == nil {
		t.Fatal("expected already-redeemed error")
	}

	// CreateGrant on unknown token
	if _, err := v.CreateGrant("vault://nope", "a", "b", "", "", 0); err == nil {
		t.Fatal("expected error granting unknown token")
	}
}

// ─── Grant expiry ─────────────────────────────────────────────────────────

func TestGrantExpired(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("x", "APIKey", "high", "a", "t", 0)
	gid, _ := v.CreateGrant(tok, "a", "b", "t", "task", time.Nanosecond)
	time.Sleep(3 * time.Millisecond)
	if _, err := v.RedeemGrant(gid, "b", "t"); err == nil {
		t.Fatal("expected expired-grant error")
	}
}

// ─── Retrieve error branches ──────────────────────────────────────────────

func TestRetrieveErrors(t *testing.T) {
	v := openTemp(t)

	// invalid format
	if _, err := v.Retrieve("not-a-token", "x"); err == nil {
		t.Fatal("expected invalid-format error")
	}
	// not found
	if _, err := v.Retrieve("vault://missing", "x"); err == nil {
		t.Fatal("expected not-found error")
	}
	// expired
	tok, _ := v.Store("v", "APIKey", "high", "a", "t", time.Nanosecond)
	time.Sleep(3 * time.Millisecond)
	if _, err := v.Retrieve(tok, "x"); err == nil {
		t.Fatal("expected expired error")
	}
	// inspect missing
	if _, err := v.Inspect("vault://missing"); err == nil {
		t.Fatal("expected inspect not-found")
	}
}

// Removing a name must also remove the profile row, or the operation silently
// half-works: the name disappears while the profile row keeps the whole
// credential chain pinned against garbage collection forever.
func TestDeleteLabelRemovesProfileRowSoChainIsCollectable(t *testing.T) {
	v := openTemp(t)
	secret, _ := v.Store("sk-value", "AWSSecretKey", "critical", "akasha-discover", "t", 0)
	mapJSON := `{"secret_access_key":"` + secret + `"}`
	mapTok, _ := v.Store(mapJSON, "AWSCredentialMap", "critical", "akasha-discover", "t", 0)
	if err := v.SetLabel("aws:stale", mapTok); err != nil {
		t.Fatal(err)
	}
	if err := v.SaveProfile("aws", "stale", mapTok, nil); err != nil {
		t.Fatal(err)
	}

	// Before removal the chain is anchored and must survive a purge.
	if _, err := v.PurgeOrphans(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Inspect(mapTok); err != nil {
		t.Fatalf("a labelled chain must not be collected: %v", err)
	}

	tok, err := v.DeleteLabel("aws:stale")
	if err != nil {
		t.Fatal(err)
	}
	if tok != mapTok {
		t.Errorf("DeleteLabel returned %q, want the bound token %q", tok, mapTok)
	}
	if _, err := v.GetLabel("aws:stale"); err == nil {
		t.Error("label still resolves after removal")
	}
	if _, err := v.GetProfile("aws", "stale"); err == nil {
		t.Error("profile row survived — the chain is still pinned and can never be collected")
	}

	// Now unreachable, so discovery-created entries become collectable.
	if _, err := v.PurgeOrphans(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Inspect(mapTok); err == nil {
		t.Error("unbound discovery chain should have been collected")
	}
	if _, err := v.Inspect(secret); err == nil {
		t.Error("the underlying field token should have been collected too")
	}
}

// Unbinding removes a NAME. A secret an agent stored is never destroyed as a
// side effect — PurgeOrphans only collects entries the discovery flows created.
func TestDeleteLabelDoesNotDestroyAgentStoredSecrets(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("agent-secret", "APIKey", "critical", "some-agent", "tool", 0)
	v.SetLabel("svc:x", tok)

	if _, err := v.DeleteLabel("svc:x"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.PurgeOrphans(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Inspect(tok); err != nil {
		t.Errorf("an agent-stored secret must survive losing its name: %v", err)
	}
}

// A typo must be reported, not silently succeed against nothing.
func TestDeleteLabelUnknownNameErrors(t *testing.T) {
	v := openTemp(t)
	if _, err := v.DeleteLabel("aws:nope"); err == nil {
		t.Error("expected an error removing a label that does not exist")
	}
}

// Other names for the same credential must keep working.
func TestDeleteLabelLeavesSiblingNamesIntact(t *testing.T) {
	v := openTemp(t)
	tok, _ := v.Store("v", "APIKey", "high", "a", "t", 0)
	v.SetLabel("aws:one", tok)
	v.SetLabel("aws:two", tok)

	if _, err := v.DeleteLabel("aws:one"); err != nil {
		t.Fatal(err)
	}
	if got, err := v.GetLabel("aws:two"); err != nil || got != tok {
		t.Errorf("sibling label broken: %q %v", got, err)
	}
}
