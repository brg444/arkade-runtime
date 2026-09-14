package application

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Bitcoin lifecycle fixtures enroll shared Spending with optional Ledger Savings.
func bitcoinAccountFixture(t *testing.T, network, tier string) (*env, string) {
	t.Helper()
	e := newUnenrolledEnvForNetwork(t, network)
	e.svc.LedgerSavingsEnabled, e.svc.LightEnabled = true, true
	selected, err := program.DefaultSpendingPolicyFor(network)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := program.SpendingPolicyDigestHexFor(network, selected)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := e.ledger.PutInvite(hash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	start, err := e.svc.StartEnrollment(token, EnrollStartRequest{ProtectionTier: tier, SpendingPolicy: selected, SpendingPolicyDigest: policyDigest})
	if err != nil {
		t.Fatal(err)
	}
	exitKey := func(origin savings.LedgerAccountOrigin) string {
		key, err := savings.LedgerSpendingExitKey(origin, network)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := key.ECPubKey()
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(schnorr.SerializePubKey(pub))
	}
	request := attestedFinish(t, e.svc, start, e.p256, e.credID, RegisterRequest{})
	request.PhoneDirectP256 = hex.EncodeToString(webauthn.CompressedP256(e.direct))
	request.PhoneBIP340Pub = hex.EncodeToString(e.hot.PubKey().SerializeCompressed())
	request.VtxoBoardingProgram = program.VaultBoardV1
	request.VaultBoardingBIP340Pub = hex.EncodeToString(schnorr.SerializePubKey(e.boarding.PubKey()))
	if tier != program.ProtectionTierLight {
		signer := newLedgerTransitionFixtureForNetwork(t, tier == program.ProtectionTierAdvanced, network)
		request.ExternalOwnerWalletXOnly = exitKey(signer.in.Hardware)
		if signer.in.Recovery != nil {
			request.RecoveryXOnly = exitKey(*signer.in.Recovery)
		}
		request.LedgerSavings = &LedgerSavingsEnrollmentRequest{TemplateVersion: savings.LedgerNativeTemplate, Phone: signer.in.Phone, Hardware: signer.in.Hardware, Recovery: signer.in.Recovery}
	}
	proposed, err := e.svc.ProposeEnrollment(token, request)
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorHash = proposed.DescriptorHash
	status, err := e.svc.FinishEnrollment(t.Context(), token, request)
	if err != nil {
		t.Fatal(err)
	}
	if tier == program.ProtectionTierLight {
		if status.LedgerSavings != nil || status.TemplateVersion != program.SpendingOnlyTemplate {
			t.Fatal("shared Spending account required")
		}
	} else if status.LedgerSavings == nil || status.TemplateVersion != savings.LedgerNativeTemplate {
		t.Fatal("Ledger account required")
	}
	c, err := e.svc.bitcoinPaymentContext(status.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	expiry := now.Add(24 * time.Hour).Unix()
	e.svc.ArkResolver = stubArkResolver{
		network: network, signer: e.svc.operatorSignerPub(),
		vtxos:     []ports.ResolvedVtxo{{Txid: strings.Repeat("01", 32), ValueSats: 80000, Script: c.spending.Tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{strings.Repeat("bb", 32)}}},
		feePolicy: ports.IntentFeePolicy{OffchainInput: "100.0"},
	}
	return e, status.VaultID
}
