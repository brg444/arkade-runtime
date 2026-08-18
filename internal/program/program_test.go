package program

import "testing"

func TestPinsMatchPublishedNames(t *testing.T) {
	if LeftoverVaultID != "operational-vault-v1" {
		t.Fatal(LeftoverVaultID)
	}
	if PolicyVersion == "" || LeftoverV4Template == "" || DustSats <= 0 {
		t.Fatal("empty program pin")
	}
}
