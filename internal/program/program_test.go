package program

import "testing"

func TestPinsMatchPublishedNames(t *testing.T) {
	if LeftoverVaultID != "operational-vault-v1" {
		t.Fatal(LeftoverVaultID)
	}
	if PolicyVersion == "" || LeftoverV4Template == "" || DustSats <= 0 {
		t.Fatal("empty program pin")
	}
	if VaultPolicyV1 != "vault-policy-v1" || VaultPolicyV1Schema != "arkade-vault/vtxo-policy-v1" {
		t.Fatal("vault-policy-v1 program pin drifted")
	}
	if VaultPolicyV1Template != "vault-policy-v1-collaborative-4pub" {
		t.Fatal(VaultPolicyV1Template)
	}
	if NetworkMutinynet != "mutinynet" {
		t.Fatal(NetworkMutinynet)
	}
}
