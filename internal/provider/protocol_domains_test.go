package provider

import (
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
)

func TestFrozenProviderProtocolDomains(t *testing.T) {
	if publicDescriptorSchema != "arkade-vault/v4" {
		t.Fatalf("public descriptor schema = %s", publicDescriptorSchema)
	}
	if enrollmentPoPDomain != "arkade-2fa-vault/enrollment-pop/v3" {
		t.Fatalf("enrollment pop domain = %s", enrollmentPoPDomain)
	}
	if recoveryBindingDomain != "arkade-2fa-vault/recovery-binding/v1" {
		t.Fatalf("passkey binding domain = %s", recoveryBindingDomain)
	}
	if passkeyProofDomain != "arkade-2fa-vault/passkey-proof/v1" {
		t.Fatalf("passkey proof domain = %s", passkeyProofDomain)
	}
	if regtestCredentialIntegrityDomain != "arkade-2fa-vault/regtest-public-credential-integrity-key/v1" {
		t.Fatalf("regtest integrity domain = %s", regtestCredentialIntegrityDomain)
	}
	if fixture.TemplateVersion == fixture.LeftoverV3TemplateVersion {
		t.Fatal("current template must not equal the leftover v3 template")
	}
}
