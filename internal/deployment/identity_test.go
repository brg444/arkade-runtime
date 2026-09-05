package deployment

import "testing"

func TestIdentityForRejectsUnknownNetworks(t *testing.T) {
	if _, err := IdentityFor("regtest"); err == nil {
		t.Fatal("regtest accepted")
	}
	if _, err := IdentityFor(""); err == nil {
		t.Fatal("empty network accepted")
	}
}

func TestIdentityForMainnetPinsLiveOperator(t *testing.T) {
	id, err := IdentityFor(NetworkMainnet)
	if err != nil {
		t.Fatal(err)
	}
	if id.OperatorGetInfoNetwork != "bitcoin" || id.OperatorOrigin != MainnetArkIndexerOrigin {
		t.Fatalf("%+v", id)
	}
	if id.CheckpointDelaySeconds != 605184 || id.VtxoTreeExpirySeconds != 2592256 {
		t.Fatalf("%+v", id)
	}
	if id.EmulatorPubHex != MainnetArkadeCosignerPubHex || id.OperatorSignerPubHex != MainnetOperatorSignerPubHex {
		t.Fatalf("%+v", id)
	}
}

func TestMainnetWalletHostsArePinnedProductNames(t *testing.T) {
	if MainnetWalletOrigin != "https://app.getvaulted.xyz" || MainnetWalletRPID != "app.getvaulted.xyz" {
		t.Fatalf("%s %s", MainnetWalletOrigin, MainnetWalletRPID)
	}
	if MainnetRCOrigin != "https://rc.getvaulted.xyz" || MainnetRCRPID != "rc.getvaulted.xyz" {
		t.Fatalf("%s %s", MainnetRCOrigin, MainnetRCRPID)
	}
	if !AllowedMainnetWallet(MainnetWalletOrigin, MainnetWalletRPID) || !AllowedMainnetWallet(MainnetRCOrigin, MainnetRCRPID) {
		t.Fatal("pinned hosts rejected")
	}
	if AllowedMainnetWallet("https://getvaulted.xyz", "getvaulted.xyz") {
		t.Fatal("marketing origin accepted")
	}
	if AllowedMainnetWallet("https://guardian.getvaulted.xyz", "guardian.getvaulted.xyz") {
		t.Fatal("guardian origin accepted as wallet RP")
	}
}
