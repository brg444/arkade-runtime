package fixture

import (
	"os"
	"strings"
	"testing"
)

func TestFixtureDoesNotExportOfflinePrivateScalar(t *testing.T) {
	raw, err := os.ReadFile("fixture.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "OfflinePrivHex") {
		t.Fatal("fixture must not export an offline private scalar")
	}
	if strings.Contains(text, "0000000000000000000000000000000000000000000000000000000000000001") {
		t.Fatal("fixture must not embed secp256k1 scalar 1")
	}
	if RecoveryKeyPubHex != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Fatalf("RecoveryKeyPubHex = %s, want generator G", RecoveryKeyPubHex)
	}
	if ExternalOwnerWalletPubHex != "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" {
		t.Fatalf("ExternalOwnerWalletPubHex = %s, want generator 2G", ExternalOwnerWalletPubHex)
	}
}

func TestFrozenProductContract(t *testing.T) {
	if TemplateVersion != "phone-hww-recovery-savings-v1" {
		t.Fatalf("TemplateVersion = %s", TemplateVersion)
	}
	if PolicyVersion != "vault-spending-policy-v1" {
		t.Fatalf("PolicyVersion = %s", PolicyVersion)
	}
	if HardwareRecoveryCSVBlocks != 6 || PhoneRecoveryCSVBlocks != 144 || RecoveryCSVBlocks != 288 {
		t.Fatalf("recovery delays = %d/%d/%d", HardwareRecoveryCSVBlocks, PhoneRecoveryCSVBlocks, RecoveryCSVBlocks)
	}
	if PRFSalt != "arkade-2fa-vault/prf/v1" || HKDFInfo != "arkade-2fa-vault/kek/v1" || DirectP256HKDFInfo != "arkade-2fa-vault/direct-p256/v1" {
		t.Fatal("client HKDF domains drifted")
	}
}
