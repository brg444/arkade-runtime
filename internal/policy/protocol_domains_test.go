package policy

import "testing"

// TestFrozenProtocolDomains pins each HMAC/HKDF string as its own
// contract. The suffix is not a release. credential-record/v3 and
// schema 7 and template …-v5 are independent axes — see docs/versions.md.
func TestFrozenProtocolDomains(t *testing.T) {
	pairs := []struct {
		got, want string
	}{
		{credentialIntegrityDomain, "arkade-2fa-vault/credential-record/v3"},
		{issuanceIntegrityDomain, "arkade-2fa-vault/issuance-record/v3"},
		{issuanceMACSalt, "arkade-2fa-vault/issuance-mac/v3"},
		{vaultRecordMACDomain, "arkade-2fa-vault/vault-record/v4"},
		{vaultCredentialMACDomain, "arkade-2fa-vault/vault-credential/v1"},
		{sessionMACDomain, "arkade-2fa-vault/recovery-session/v2"},
		{credentialEnvelopeDomain, "arkade-2fa-vault/credential-envelope/v1"},
		{vaultEnvelopeDomain, "arkade-2fa-vault/vault-envelope/v4"},
		{vaultEnvelopeMACSalt, "arkade-2fa-vault/vault-envelope-mac/v4"},
		{vaultCosignerHKDFSalt, "arkade-2fa-vault/vault-cosigner/hkdf-sha256-v1"},
		{vaultCosignerHKDFInfo, "vault-cosigner/v1"},
		{CosignerModeLegacyDirectV0, "legacy-direct-v0"},
		{CosignerModeHKDFSHA256V1, "hkdf-sha256-v1"},
		{LegacyFirstVaultID, "operational-vault-v1"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("domain %q drifted to %q", p.want, p.got)
		}
	}
}
