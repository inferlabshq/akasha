package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// Closing the DB makes every query fail, exercising the error branches in the
// store/retrieve/registry methods that a happy-path test can't reach.
func TestMethodsOnClosedDB(t *testing.T) {
	v := openTemp(t)
	// Seed a token + grant + label before closing so methods get past their
	// first lookups into the failing query.
	tok, _ := v.Store("v", "APIKey", "high", "a", "t", 0)
	gid, _ := v.CreateGrant(tok, "a", "b", "t", "task", 0)
	v.SetLabel("svc:x", tok)
	v.Close()

	if _, err := v.Store("x", "c", "r", "a", "t", 0); err == nil {
		t.Error("Store on closed db should error")
	}
	if _, err := v.Retrieve(tok, "t"); err == nil {
		t.Error("Retrieve on closed db should error")
	}
	if _, err := v.Inspect(tok); err == nil {
		t.Error("Inspect on closed db should error")
	}
	if _, err := v.InspectGrant(gid); err == nil {
		t.Error("InspectGrant on closed db should error")
	}
	if _, err := v.RedeemGrant(gid, "b", "t"); err == nil {
		t.Error("RedeemGrant on closed db should error")
	}
	if _, _, err := v.CreateAgentKey("z"); err == nil {
		t.Error("CreateAgentKey on closed db should error")
	}
	if _, err := v.VerifyAgentKey("agt_x"); err == nil {
		t.Error("VerifyAgentKey on closed db should error")
	}
	if _, err := v.ListAgentKeys(); err == nil {
		t.Error("ListAgentKeys on closed db should error")
	}
	if err := v.RevokeAgentKey("agt_x"); err == nil {
		t.Error("RevokeAgentKey on closed db should error")
	}
	if err := v.SetLabel("a", "b"); err == nil {
		t.Error("SetLabel on closed db should error")
	}
	if _, err := v.GetLabel("svc:x"); err == nil {
		t.Error("GetLabel on closed db should error")
	}
	if _, err := v.ListLabels(""); err == nil {
		t.Error("ListLabels on closed db should error")
	}
	if err := v.SaveProfile("p", "q", tok, nil); err == nil {
		t.Error("SaveProfile on closed db should error")
	}
	if _, err := v.GetProfile("p", "q"); err == nil {
		t.Error("GetProfile on closed db should error")
	}
	if _, err := v.ListProfiles(""); err == nil {
		t.Error("ListProfiles on closed db should error")
	}
	if _, err := v.PurgeExpired(); err == nil {
		t.Error("PurgeExpired on closed db should error")
	}
	if _, err := v.PurgeOrphans(); err == nil {
		t.Error("PurgeOrphans on closed db should error")
	}
}

// Passphrase mode: exercises the Argon2id fold + loadOrCreateArgon2Salt (create
// on first open, load on second).
func TestPassphraseRoundtrip(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "vault.db")
	pass := vault.Options{Passphrase: []byte("correct horse battery staple"), AllowNewVaultKey: true}

	v, err := vault.Open(db, pass)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := v.Store("secret", "APIKey", "high", "a", "t", 0)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Reopen with the same passphrase → salt loaded, key recombined, decrypts.
	v2, err := vault.Open(db, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	got, err := v2.Retrieve(tok, "t")
	if err != nil || got != "secret" {
		t.Fatalf("passphrase reopen: got %q err %v", got, err)
	}
}

func TestOpenBadPath(t *testing.T) {
	// A db path under a non-existent directory fails during migrate.
	if _, err := vault.Open("/no/such/dir/vault.db", vault.Options{AllowNewVaultKey: true}); err == nil {
		t.Fatal("expected error opening vault in missing dir")
	}
}

func TestRestoreCorruptBackup(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.akb")
	os.WriteFile(bad, []byte("xx"), 0600) // too short / wrong version
	if err := vault.RestoreKey(filepath.Join(dir, "v.db"), bad, []byte("pw")); err == nil {
		t.Fatal("expected error restoring a corrupt backup")
	}
	// missing file
	if err := vault.RestoreKey(filepath.Join(dir, "v.db"), filepath.Join(dir, "nope.akb"), []byte("pw")); err == nil {
		t.Fatal("expected error restoring a missing backup")
	}
}
