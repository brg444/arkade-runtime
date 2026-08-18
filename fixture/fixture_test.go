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
	if LeftoverV3TemplateVersion != "phone-direct-p256-routine-3of3-admin-2of2-v3" {
		t.Fatalf("LeftoverV3TemplateVersion = %s", LeftoverV3TemplateVersion)
	}
}

func TestFrozenProductContract(t *testing.T) {
	if TemplateVersion != "phone-direct-p256-routine-3of3-admin-phone-hww-v4" {
		t.Fatalf("TemplateVersion = %s", TemplateVersion)
	}
	if PolicyVersion != "mandatory-change-tx50k-day100k-fee5k-feerate10-onchain-v3" {
		t.Fatalf("PolicyVersion = %s", PolicyVersion)
	}
	if OperationalCSVBlocks != 144 || SavingsCSVBlocks != 6 {
		t.Fatalf("CSV clocks = %d/%d, want device 144 / hardware 6", OperationalCSVBlocks, SavingsCSVBlocks)
	}
	if DeviceCSVBlocks != OperationalCSVBlocks || HardwareCSVBlocks != SavingsCSVBlocks {
		t.Fatal("DeviceCSV/HardwareCSV aliases must stay equal to the frozen wire names")
	}
	if PRFSalt != "arkade-2fa-vault/prf/v1" || HKDFInfo != "arkade-2fa-vault/kek/v1" || DirectP256HKDFInfo != "arkade-2fa-vault/direct-p256/v1" {
		t.Fatal("client HKDF domains drifted")
	}
}
