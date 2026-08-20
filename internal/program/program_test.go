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
	if VaultPolicyV1ExitDelay != 4608 || VaultPolicyV1ExitDelayUnit != "seconds" {
		t.Fatal("vault-policy-v1 exit hatch pin drifted")
	}
	if VaultPolicyV1ArkdMinExitDelay != 2048 || VaultPolicyV1BIP68SecondsMod != 512 {
		t.Fatal("vault-policy-v1 arkd minimum pin drifted")
	}
	if err := ValidateVaultPolicyV1ExitDelay(VaultPolicyV1ExitDelay, VaultPolicyV1ExitDelayUnit); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVaultPolicyV1ExitDelay(2048, "seconds"); err == nil {
		t.Fatal("2048s hatch must be rejected")
	}
	const mutinynet144BlocksAsSeconds = 144 * 30
	if VaultPolicyV1ExitDelay < VaultPolicyV1ArkdMinExitDelay {
		t.Fatal("product delay below arkd minimum")
	}
	if VaultPolicyV1ExitDelay < mutinynet144BlocksAsSeconds {
		t.Fatal("product delay below 144-block Mutinynet floor")
	}
	if VaultPolicyV1ExitDelay%VaultPolicyV1BIP68SecondsMod != 0 {
		t.Fatal("product delay is not a BIP68 seconds multiple")
	}
	if VaultPolicyV1PinnedDelegate != "032903b15efe236d9609da10e536fb32cdf1d144778797bbf32a9b94e86601be6a" {
		t.Fatal("pinned public delegate drifted")
	}
	if VaultPolicyV1DelegateOrigin != "https://delegator.mutinynet.arkade.sh" {
		t.Fatal(VaultPolicyV1DelegateOrigin)
	}
	if VaultPolicyV1DelegateCapability != "multi-presigned-signature" {
		t.Fatal(VaultPolicyV1DelegateCapability)
	}
	if NetworkMutinynet != "mutinynet" {
		t.Fatal(NetworkMutinynet)
	}
}
