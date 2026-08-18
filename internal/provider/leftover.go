package provider

import (
	"log"

	"github.com/brg444/arkade-vault-server/fixture"
)

// quarantineLegacyVault isolates the one retired v3 template. Multi-tenant
// boot may leave that row unloaded. Any other stored mismatch fails closed.
func quarantineLegacyVault(s *Service, vaultID, template string) bool {
	if s == nil || !s.MultiTenantEnrollment || template != fixture.LeftoverV3TemplateVersion {
		return false
	}
	log.Printf("quarantining leftover vault %s template %q", vaultID, template)
	return true
}
