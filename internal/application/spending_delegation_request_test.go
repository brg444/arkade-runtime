package application

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

func TestSpendingRenewalSetWalletVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/renewal-set-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Status Status                       `json:"status"`
		Set    spendingDelegationSetRequest `json:"set"`
		Body   json.RawMessage              `json:"body"`
		Digest string                       `json:"digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pins, err := deployment.IdentityFor(v.Status.Network)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := parsePSBT(v.Set.Plans[0].Intent.Proof)
	if err != nil {
		t.Fatal(err)
	}
	b := spendingRenewalBinding{Program: v.Set.Program, Network: v.Status.Network, VaultID: v.Status.VaultID, ProtectionTier: v.Status.ProtectionTier, OwnerPub: v.Status.PhoneBIP340Pub[2:], CosignerPub: v.Status.VtxoVaultCosignerPub[2:], OperatorPub: pins.OperatorSignerPubHex[2:], ScriptPubKey: hex.EncodeToString(proof.Inputs[1].WitnessUtxo.PkScript), SpendingPolicy: v.Status.SpendingPolicy}
	digest, err := v.Set.verifyOwner(b)
	if err != nil || hex.EncodeToString(digest) != v.Digest {
		t.Fatalf("wallet set signatures or digest: %v", err)
	}
	if v.Set.Authorization == nil {
		t.Fatal("missing direct authorization vector")
	}
	key, err := hex.DecodeString(v.Status.PhoneDirectP256)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(v.Set.Authorization.DirectSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDirectAuth(key, digest, sig); err != nil {
		t.Fatal(err)
	}
	// The vector deliberately has placeholder WebAuthn fields. This test
	// verifies actual owner/direct signatures, never a passkey ceremony.
	for _, tc := range []struct {
		name   string
		mutate func(*spendingDelegationSetRequest)
	}{
		{"subset", func(r *spendingDelegationSetRequest) { r.Plans = r.Plans[:1] }},
		{"reorder", func(r *spendingDelegationSetRequest) { r.Plans[0], r.Plans[1] = r.Plans[1], r.Plans[0] }},
		{"duplicate", func(r *spendingDelegationSetRequest) { r.Plans[1] = r.Plans[0] }},
		{"set identity", func(r *spendingDelegationSetRequest) { r.SetID = strings.Repeat("ef", 16) }},
		{"program", func(r *spendingDelegationSetRequest) { r.Program = "vault-light-policy-v1" }},
		{"deadline", func(r *spendingDelegationSetRequest) { r.Plans[0].ExpiresAt++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := v.Set
			copy.Plans = append([]spendingDelegationInput(nil), v.Set.Plans...)
			tc.mutate(&copy)
			if _, err := copy.verifyOwner(b); err == nil {
				t.Fatal("changed owner authority accepted")
			}
		})
	}
}
