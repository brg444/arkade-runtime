package policy

import "testing"

// TestFrozenProtocolDomains pins each current HMAC/HKDF string as its own
// contract. Domain suffixes are not release numbers.
func TestFrozenProtocolDomains(t *testing.T) {
	pairs := []struct {
		got, want string
	}{
		{vaultRecordMACDomain, "arkade-vault/vault-record/v2"},
		{vaultCredentialMACDomain, "arkade-vault/vault-credential/v1"},
		{sessionMACDomain, "arkade-2fa-vault/recovery-session/v2"},
		{vaultEnvelopeDomain, "arkade-vault/vault-envelope/v2"},
		{vaultEnvelopeMACSalt, "arkade-vault/vault-envelope-mac/v2"},
		{vaultCosignerHKDFSalt, "arkade-2fa-vault/vault-cosigner/hkdf-sha256-v1"},
		{vaultCosignerHKDFInfo, "vault-cosigner/v1"},
		{CosignerModeHKDFSHA256V1, "hkdf-sha256-v1"},
		{CosignerModeVtxoHKDFSHA256V1, "vtxo-hkdf-sha256-v1"},
		{vtxoVaultCosignerHKDFSalt, "arkade-2fa-vault/vtxo-vault-cosigner/hkdf-sha256-v1"},
		{vtxoVaultCosignerHKDFInfo, "vtxo-vault-cosigner/v1"},
		{vtxoOperationMACDomain, "arkade-2fa-vault/vtxo-operation/v1"},
		{vtxoBundleDigestTag, "arkade-2fa-vault/vtxo-bundle/v1"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("domain %q drifted to %q", p.want, p.got)
		}
	}
}
