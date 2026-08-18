package authorizer

import "testing"

func TestFrozenIntegrityHKDFDomains(t *testing.T) {
	if credentialIntegrityHKDFSalt != "arkade-2fa-vault/vault-cosigner-scalar-hkdf-salt/v3" {
		t.Fatalf("integrity salt = %s", credentialIntegrityHKDFSalt)
	}
	if credentialIntegrityHKDFInfo != "arkade-2fa-vault/credential-integrity-key/v3" {
		t.Fatalf("integrity info = %s", credentialIntegrityHKDFInfo)
	}
}
