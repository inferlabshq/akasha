package escrow

import "github.com/inferlabshq/akasha/daemon/internal/vault"

// Direct adapts *vault.Vault to the escrow Vault interface for callers that
// hold the vault open directly (uninstall, tests). CLI commands go through
// the daemon socket instead, which layers auth, audit, and policy on top.
type Direct struct{ *vault.Vault }

func (d Direct) ValueForLabel(name string) (string, error) {
	token, err := d.GetLabel(name)
	if err != nil {
		return "", err
	}
	return d.Retrieve(token, "akasha_restore")
}
