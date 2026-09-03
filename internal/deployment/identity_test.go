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
	if id.CheckpointDelaySeconds != 605184 || id.VtxoTreeExpirySeconds != 7776256 {
		t.Fatalf("%+v", id)
	}
	if id.EmulatorPubHex != MainnetArkadeCosignerPubHex || id.OperatorSignerPubHex != MainnetOperatorSignerPubHex {
		t.Fatalf("%+v", id)
	}
}
