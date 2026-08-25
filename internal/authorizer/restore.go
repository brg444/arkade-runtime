package authorizer

import (
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

// VerifyRestoreState authenticates an offline database and policy-sequence
// pair with the file-backed VaultCosigner. The private scalar and derived MAC
// key stay inside the authorizer boundary and are wiped before return.
func VerifyRestoreState(databasePath, sequencePath, vaultCosignerKeyFile string) (policy.RestoreStateSummary, error) {
	var summary policy.RestoreStateSummary
	vaultCosignerKey, err := LoadVaultCosignerKey(vaultCosignerKeyFile)
	if err != nil {
		return summary, err
	}
	defer wipePrivateKey(vaultCosignerKey)
	integrityKey, err := deriveCredentialIntegrityKey(vaultCosignerKey)
	if err != nil {
		return summary, fmt.Errorf("derive restore integrity key: %w", err)
	}
	defer zero(integrityKey)
	return policy.VerifyRestoreState(databasePath, sequencePath, integrityKey)
}
