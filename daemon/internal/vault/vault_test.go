package vault_test

import (
	"os"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

func openTemp(t *testing.T) *vault.Vault {
	t.Helper()
	f, err := os.CreateTemp("", "akasha-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	v, err := vault.Open(f.Name(), vault.Options{AllowNewVaultKey: true})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestStoreAndRetrieve(t *testing.T) {
	v := openTemp(t)

	token, err := v.Store("429-21-0001", "SSN", "critical", "agent-1", "lookup", 0)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if !strings.HasPrefix(token, "vault://") {
		t.Fatalf("token format wrong: %s", token)
	}

	got, err := v.Retrieve(token, "lookup")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got != "429-21-0001" {
		t.Fatalf("got %q", got)
	}
}

func TestInspect(t *testing.T) {
	v := openTemp(t)

	token, _ := v.Store("secret", "Password", "high", "agent-2", "tool", 0)
	entry, err := v.Inspect(token)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if entry.Category != "Password" {
		t.Fatalf("category: %s", entry.Category)
	}
	if entry.Risk != "high" {
		t.Fatalf("risk: %s", entry.Risk)
	}
}

func TestTokenNotFound(t *testing.T) {
	v := openTemp(t)
	_, err := v.Retrieve("vault://doesnotexist", "")
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestInvalidTokenFormat(t *testing.T) {
	v := openTemp(t)
	_, err := v.Retrieve("not-a-token", "")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestStats(t *testing.T) {
	v := openTemp(t)
	v.Store("val1", "SSN", "critical", "a", "t", 0)
	v.Store("val2", "Email", "medium", "a", "t", 0)

	total, _, err := v.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("expected 2 total, got %d", total)
	}
}

func TestCreateAndRedeemGrant(t *testing.T) {
	v := openTemp(t)
	token, _ := v.Store("4111111111111111", "CreditCard", "critical", "agent-a", "lookup", 0)

	grantID, err := v.CreateGrant(token, "agent-a", "agent-b", "charge_card", "Process refund #8821", 0)
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if !strings.HasPrefix(grantID, "grt://") {
		t.Fatalf("grant format wrong: %s", grantID)
	}

	redeemed, err := v.RedeemGrant(grantID, "agent-b", "charge_card")
	if err != nil {
		t.Fatalf("RedeemGrant: %v", err)
	}
	if redeemed != token {
		t.Fatalf("got token %q, want %q", redeemed, token)
	}

	// Single-use enforcement.
	_, err = v.RedeemGrant(grantID, "agent-b", "charge_card")
	if err == nil {
		t.Fatal("expected error on double-redeem")
	}
}

func TestGrantWrongAgent(t *testing.T) {
	v := openTemp(t)
	token, _ := v.Store("secret", "APIKey", "high", "a", "t", 0)
	grantID, _ := v.CreateGrant(token, "agent-a", "agent-b", "", "", 0)

	_, err := v.RedeemGrant(grantID, "agent-c", "")
	if err == nil {
		t.Fatal("expected error: wrong grantee")
	}
}

func TestGrantWrongTool(t *testing.T) {
	v := openTemp(t)
	token, _ := v.Store("secret", "APIKey", "high", "a", "t", 0)
	grantID, _ := v.CreateGrant(token, "agent-a", "agent-b", "send_email", "", 0)

	_, err := v.RedeemGrant(grantID, "agent-b", "charge_card")
	if err == nil {
		t.Fatal("expected error: wrong tool")
	}
}

func TestGrantUnknownToken(t *testing.T) {
	v := openTemp(t)
	_, err := v.CreateGrant("vault://doesnotexist", "a", "b", "", "", 0)
	if err == nil {
		t.Fatal("expected error granting unknown token")
	}
}

func TestRetrievedCountIncrement(t *testing.T) {
	v := openTemp(t)
	token, _ := v.Store("secret", "APIKey", "high", "a", "t", 0)

	v.Retrieve(token, "t")
	v.Retrieve(token, "t")

	entry, _ := v.Inspect(token)
	if entry.RetrievedCount != 2 {
		t.Fatalf("expected retrieved_count=2, got %d", entry.RetrievedCount)
	}
}
