package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// Reading a vault's keychain account must never create the vault. It used to:
// `mode=ro` is ignored outside a file: URI, so `akasha sandbox doctor --db X`
// left an empty X on disk.
func TestKeychainProbeForAbsentDBCreatesNothing(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vault.db")
	svc, acct := KeychainProbeFor(db)
	if svc != keyringService || acct != keyringMLKEMSK {
		t.Fatalf("absent db should fall back to the legacy account, got %s/%s", svc, acct)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatalf("probing an absent vault created it: %v", err)
	}
}
