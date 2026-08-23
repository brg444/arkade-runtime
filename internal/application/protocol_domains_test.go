package application

import "testing"

func TestFrozenProviderProtocolDomains(t *testing.T) {
	if recoveryBindingDomain != "arkade-vault/recovery-binding/v2" {
		t.Fatalf("passkey binding domain = %s", recoveryBindingDomain)
	}
	if passkeyProofDomain != "arkade-2fa-vault/passkey-proof/v1" {
		t.Fatalf("passkey proof domain = %s", passkeyProofDomain)
	}
}
