package application

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Produced by Wallet.makeRegisterIntentSignature in the wallet repository's
// savingsSetupStore.test.ts. All keys and outpoints are public test fixtures.
func TestSavingsSetupActualSDKIntent(t *testing.T) {
	raw, err := os.ReadFile("testdata/savings-setup-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Status       Status                     `json:"status"`
		Context      spendingRenewalBinding     `json:"context"`
		Prepared     savingsSetupPrepared       `json:"prepared"`
		Prepare      savingsSetupPrepareRequest `json:"prepare"`
		DeleteIntent lightDelegateIntent        `json:"deleteIntent"`
		PSBT         string                     `json:"psbt"`
		Message      string                     `json:"message"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub := func(s string) *btcec.PublicKey {
		k, err := btcec.ParsePubKey(mustDecodeRenewalHex(s))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	b := v.Context
	pins, err := program.PinsFor(b.Network)
	if err != nil {
		t.Fatal(err)
	}
	p := policy.VaultPolicyV1Params{Network: b.Network, UserPub: mustDecodeRenewalHex(b.OwnerPub), VtxoVaultCosignerPub: mustDecodeRenewalHex(b.CosignerPub), ArkdServerPub: mustDecodeRenewalHex(b.OperatorPub), DelegatePub: mustDecodeRenewalHex(pins.DelegatePub)[1:], ExitDevicePub: mustDecodeRenewalHex(b.OwnerPub), ExitHardwarePub: schnorr.SerializePubKey(pub(v.Status.ExternalOwnerWalletPub))}
	built, err := policy.BuildVaultPolicyV1Tree(p)
	if err != nil {
		t.Fatal(err)
	}
	cosigner, _ := schnorr.ParsePubKey(p.VtxoVaultCosignerPub)
	operator, _ := schnorr.ParsePubKey(p.ArkdServerPub)
	tree := &vtxoPolicyTree{CosignerPub: cosigner, ArkdPub: operator, PkScript: built.PkScript, SpendLeaf: built.SpendScript, SpendControl: built.SpendControlBlock, RevealedScripts: built.RevealedScripts}
	hash, err := b.digest()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := deployment.IdentityFor(b.Network)
	scope, err := newVtxoKeyContext(b.VaultID, b.Network, mustDecodeRenewalHex(identity.OperatorSignerPubHex))
	if err != nil {
		t.Fatal(err)
	}
	origin := v.Status.ConnectorEnrollment
	c := savingsSetupContext{
		spending: renewalContract{spendingRenewalContext: spendingRenewalContext{Binding: b, DescriptorHash: hash, Tree: tree, KeyScope: scope, vaultParams: &p}},
		savings:  savings.FamilyInput{VaultID: b.VaultID, Network: b.Network, Phone: pub(v.Status.PhoneBIP340Pub), Hardware: pub(v.Status.ExternalOwnerWalletPub), PhoneDirectP256: mustDecodeRenewalHex(v.Status.PhoneDirectP256), VaultCosignerBase: pub(v.Status.VaultCosignerBasePub), ArkadeCosignerBase: pub(v.Status.ArkadeCosignerBasePub), TemplateVersion: v.Status.TemplateVersion, ServerFreeClawback: true, ProtectionTier: b.ProtectionTier, SpendingPolicy: b.SpendingPolicy},
		origin:   connector.KeyOrigin{Type: connector.Kind(origin.ConnectorType), PublicKey: mustDecodeRenewalHex(origin.ConnectorPub), Fingerprint: origin.ConnectorFingerprint, Path: origin.ConnectorPath},
	}
	digest, err := v.Prepared.Plan.digest(c)
	if err != nil || hex.EncodeToString(digest) != v.Prepared.PlanDigest {
		t.Fatalf("SDK plan: %v", err)
	}
	prepareDigest, err := v.Prepare.digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.ParseSignature(mustDecodeRenewalHex(v.Prepare.OwnerSignature))
	if err != nil || !sig.Verify(prepareDigest, pub(v.Status.PhoneBIP340Pub)) {
		t.Fatal("SDK prepare signature")
	}
	if err := verifyRenewalDelete(v.DeleteIntent, v.Prepared.Plan.batchInput(), c.spending); err != nil {
		t.Fatalf("stock SDK deletion: %v", err)
	}
	if _, err := verifySavingsSetupRegistration(v.PSBT, v.Message, v.Prepared.Plan, c); err != nil {
		t.Fatalf("stock SDK intent: %v", err)
	}
}
