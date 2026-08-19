package application

import (
	"log"

	"github.com/brg444/arkade-vault-server/internal/program"
)

// quarantineLegacyVault isolates one retired template id that may still
// exist on the live ledger. Other known templates still load and sign.
func quarantineLegacyVault(s *Service, vaultID, template string) bool {
	if s == nil || !s.MultiTenantEnrollment {
		return false
	}
	if template == program.LeftoverV3Template {
		log.Printf("quarantining leftover vault %s template %q", vaultID, template)
		return true
	}
	return false
}
