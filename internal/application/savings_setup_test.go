package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func setupFundingFixture(t *testing.T, network, tier string) (*env, bitcoinPaymentContext, bitcoinPaymentPrepared, savingsSetupPrepareRequest) {
	t.Helper()
	e, _, set := spendingDelegationFixture(t, network, tier, true)
	c, err := e.svc.bitcoinPaymentContext(set.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	coins, err := e.svc.ArkResolver.SpendableVtxos(t.Context(), c.spending.Tree.PkScript)
	if err != nil {
		t.Fatal(err)
	}
	r := savingsSetupPrepareRequest{VaultID: set.VaultID, OperationID: strings.Repeat("89", 16), Txid: coins[0].Txid, Vout: coins[0].Vout, ReserveCount: 2, ExpiresAt: e.svc.vtxoNow().Add(4 * time.Minute).Unix()}
	digest, err := r.digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(e.hot, digest)
	if err != nil {
		t.Fatal(err)
	}
	r.OwnerSignature = hex.EncodeToString(sig.Serialize())
	prepared, err := e.svc.prepareSavingsSetup(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	return e, c, prepared, r
}

func setupRegistrationFixture(t *testing.T, e *env, c bitcoinPaymentContext, p bitcoinPaymentPlan, session *btcec.PrivateKey, outputs []*wire.TxOut) lightRenewalRegisterRequest {
	t.Helper()
	indexes := []int{1}
	if len(p.onchainOutputs()) == 2 {
		indexes = append(indexes, 2)
	}
	message, err := (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: indexes, ExpireAt: p.RegisterExpireAt, CosignersPublicKeys: []string{hex.EncodeToString(session.PubKey().SerializeCompressed())}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := chainhash.NewHashFromStr(p.Txid)
	tree := c.spending.Tree
	proof, err := intent.New(message, []intent.Input{{OutPoint: &wire.OutPoint{Hash: *hash, Index: p.Vout}, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: &wire.TxOut{Value: p.ValueSats, PkScript: tree.PkScript}}}, outputs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{Script: tree.SpendLeaf, ControlBlock: tree.SpendControl, LeafVersion: txscript.BaseLeafVersion}}
		if i == 1 {
			if err := txutils.SetArkPsbtField(&proof.Packet, i, txutils.VtxoTaprootTreeField, txutils.TapTree(tree.RevealedScripts)); err != nil {
				t.Fatal(err)
			}
		}
		sig, err := signTapLeafAtWithSighash(&proof.Packet, i, e.hot, tree.SpendLeaf, txscript.SigHashAll)
		if err != nil {
			t.Fatal(err)
		}
		proof.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	}
	raw, _ := proof.B64Encode()
	digest, err := p.digest(c)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.SynthWithSignCount(e.p256, e.credID, digest, e.svc.ClientOrigin(), e.svc.runtimeConfig().RPID, true, true, 8)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.SignDigestLowS(e.direct, digest)
	if err != nil {
		t.Fatal(err)
	}
	return lightRenewalRegisterRequest{VaultID: p.VaultID, OperationID: p.OperationID, PSBT: raw, Message: message, Assertion: WebAuthnAssertionRequest{CredentialID: hex.EncodeToString(e.credID), ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature)}, DirectSig: hex.EncodeToString(direct)}
}

func TestSavingsSetupPrepareUsesEnrolledSignerAndChargesAllowance(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		for _, tier := range []string{"standard", "advanced"} {
			t.Run(network+"/"+tier, func(t *testing.T) {
				e, c, prepared, r := setupFundingFixture(t, network, tier)
				if prepared.Plan.ReserveCount != 2 || prepared.Plan.ReserveSats != 500 {
					t.Fatal("wrong reserve arrangement")
				}
				used, err := e.ledger.SpentInPeriod(t.Context(), r.VaultID, "")
				if err != nil || used != 1000+prepared.Plan.FeeSats {
					t.Fatalf("outflow %d %v", used, err)
				}
				replay, err := e.svc.prepareSavingsSetup(t.Context(), r)
				if err != nil || replay.PlanDigest != prepared.PlanDigest {
					t.Fatalf("exact retry changed: %v", err)
				}
				changed := prepared.Plan
				changed.ReserveScript = c.spending.Binding.ScriptPubKey
				if _, err := changed.digest(c); err == nil {
					t.Fatal("arbitrary destination accepted")
				}
				changed = prepared.Plan
				changed.ReserveSats = 1000
				if _, err := changed.digest(c); err == nil {
					t.Fatal("incorrect output value accepted")
				}
				r.ReserveCount = 1
				if _, err := e.svc.prepareSavingsSetup(t.Context(), r); err == nil {
					t.Fatal("changed signed request accepted")
				}
			})
		}
	}
}

func TestSavingsSetupRegistrationRejectsSignedOutputSubstitution(t *testing.T) {
	e, c, prepared, _ := setupFundingFixture(t, "mainnet", "standard")
	session, _ := btcec.NewPrivateKey()
	for _, change := range []string{"none", "signer", "change", "amount", "missing"} {
		t.Run(change, func(t *testing.T) {
			outputs := prepared.Plan.outputs(c)
			switch change {
			case "signer":
				outputs[1].PkScript = c.spending.Tree.PkScript
			case "change":
				outputs[0].PkScript = outputs[1].PkScript
			case "amount":
				outputs[1].Value++
			case "missing":
				outputs = outputs[:2]
			}
			request := setupRegistrationFixture(t, e, c, prepared.Plan, session, outputs)
			_, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
			if (err == nil) != (change == "none") {
				t.Fatalf("%s: %v", change, err)
			}
		})
	}
}

func TestSavingsSetupFinalRequiresDistinctOutputsAndSignedChange(t *testing.T) {
	e, c, prepared, _ := setupFundingFixture(t, "mainnet", "advanced")
	session, _ := btcec.NewPrivateKey()
	operatorSession, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	registration, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"none", "merged", "missing", "destination", "value", "change signature"} {
		t.Run(change, func(t *testing.T) {
			outputs := prepared.Plan.outputs(c)[1:]
			switch change {
			case "merged":
				outputs[0].Value = 1000
				outputs = outputs[:1]
			case "missing":
				outputs = outputs[:1]
			case "destination":
				outputs[1].PkScript = c.spending.Tree.PkScript
			case "value":
				outputs[1].Value--
			}
			f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), descriptor: light.Descriptor{Params: light.Params{Network: c.spending.Binding.Network}}, tree: c.spending.Tree, owner: e.hot}
			_, _, evidence := buildSpendingBatchEvidenceFixture(t, f, registration, session, operatorSession, outputs)
			if change == "change signature" {
				packet, _ := parsePSBT(evidence.VtxoTree[0].Tx)
				packet.Inputs[0].TaprootKeySpendSig = nil
				evidence.VtxoTree[0].Tx, _ = packet.B64Encode()
			}
			_, err := verifyBitcoinPaymentFinal(evidence, prepared.Plan, c, registration)
			if (err == nil) != (change == "none") {
				t.Fatalf("%s: %v", change, err)
			}
			if change == "none" {
				signed, err := e.svc.keys.bitcoinPaymentAuthorization(t.Context(), bitcoinPaymentAuthorization{context: c, plan: prepared.Plan, registrationPSBT: request.PSBT, registrationMessage: request.Message, final: &evidence})
				if err != nil || signed == "" {
					t.Fatalf("scoped signing failed: %v", err)
				}
			}
		})
	}
}

func TestSavingsSetupLostRegisterResponseDoesNotDispatchAgain(t *testing.T) {
	e, c, prepared, _ := setupFundingFixture(t, "mainnet", "standard")
	session, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	operator := &lightRenewalTestOperator{registerErr: fmt.Errorf("response lost")}
	e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	for i := 0; i < 2; i++ {
		result, err := e.svc.registerBitcoinPayment(t.Context(), request)
		if err != nil || result.State != "uncertain" {
			t.Fatalf("retry: %+v %v", result, err)
		}
	}
	if operator.registers != 1 {
		t.Fatal("registration submitted twice")
	}
	if err := intent.Verify(operator.signedProof, request.Message, []*btcec.PublicKey{c.spending.Tree.ArkdPub}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := e.svc.Stores.LightRenewal.GetLightRenewal(t.Context(), prepared.Plan.OperationID)
	if err != nil || snapshot.Operation.Kind != policy.SavingsSetupBatchKind {
		t.Fatal("wrong journal")
	}
	var recorded lightRenewalRegistrationEvidence
	if json.Unmarshal([]byte(snapshot.Events["register_authorized"].Evidence), &recorded) != nil || recorded.PSBT != request.PSBT {
		t.Fatal("approval was not retained")
	}
}

func TestSavingsSetupSignedPrepareExpiryCannotCreateLateReservation(t *testing.T) {
	e, _, prepared, r := setupFundingFixture(t, "mainnet", "standard")
	r.OperationID = strings.Repeat("90", 16)
	r.ExpiresAt = e.svc.vtxoNow().Add(-time.Second).Unix()
	digest, _ := r.digest()
	sig, _ := schnorr.Sign(e.hot, digest)
	r.OwnerSignature = hex.EncodeToString(sig.Serialize())
	if _, err := e.svc.prepareSavingsSetup(t.Context(), r); err == nil {
		t.Fatal("expired prepare accepted")
	}
	result, err := e.svc.reconcileBitcoinPayment(t.Context(), lightRenewalOperationRequest{VaultID: r.VaultID, OperationID: r.OperationID})
	if err != nil || result.State != "not_found" {
		t.Fatalf("absence: %+v %v", result, err)
	}
	result, err = e.svc.releaseBitcoinPayment(t.Context(), bitcoinPaymentReleaseRequest{VaultID: r.VaultID, OperationID: prepared.Plan.OperationID})
	if err != nil || result.State != "cancelled" {
		t.Fatalf("cancel: %+v %v", result, err)
	}
	used, err := e.ledger.SpentInPeriod(t.Context(), r.VaultID, "")
	if err != nil || used != 0 {
		t.Fatalf("cancelled setup still charged: %d %v", used, err)
	}
}

func TestSavingsSetupLostFinalCannotReleaseOrSubmitTwice(t *testing.T) {
	e, c, prepared, _ := setupFundingFixture(t, "mainnet", "standard")
	session, _ := btcec.NewPrivateKey()
	operatorSession, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	operator := &lightRenewalTestOperator{finalErr: fmt.Errorf("response lost")}
	e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	result, err := e.svc.registerBitcoinPayment(t.Context(), request)
	if err != nil || result.State != "registered" {
		t.Fatalf("register: %+v %v", result, err)
	}
	registration, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
	if err != nil {
		t.Fatal(err)
	}
	f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), descriptor: light.Descriptor{Params: light.Params{Network: c.spending.Binding.Network}}, tree: c.spending.Tree, owner: e.hot}
	_, _, evidence := buildSpendingBatchEvidenceFixture(t, f, registration, session, operatorSession, prepared.Plan.outputs(c)[1:])
	final := lightRenewalFinalRequest{VaultID: request.VaultID, OperationID: request.OperationID, Evidence: evidence}
	for i := 0; i < 2; i++ {
		result, err = e.svc.finalizeBitcoinPayment(t.Context(), final)
		if err != nil || result.State != "uncertain" {
			t.Fatalf("final: %+v %v", result, err)
		}
	}
	if operator.finals != 1 {
		t.Fatalf("dispatched %d times", operator.finals)
	}
	result, err = e.svc.releaseBitcoinPayment(t.Context(), bitcoinPaymentReleaseRequest{VaultID: request.VaultID, OperationID: request.OperationID})
	if err != nil || result.State != "uncertain" {
		t.Fatalf("unsafe release: %+v %v", result, err)
	}
	used, err := e.ledger.SpentInPeriod(t.Context(), request.VaultID, "")
	if err != nil || used != 1000+prepared.Plan.FeeSats {
		t.Fatalf("lost final allowance: %d %v", used, err)
	}
}

func TestSavingsSetupPublicRoutes(t *testing.T) {
	e, c, prepared, request := setupFundingFixture(t, "mainnet", "standard")
	handler := testAuthorizer(e.svc)
	var info struct {
		Version        int    `json:"version"`
		DescriptorHash string `json:"descriptorHash"`
	}
	if err := json.Unmarshal(httpJSON(t, handler, "GET", "/v1/vtxo/savings-setup/info?vaultId="+request.VaultID, nil), &info); err != nil {
		t.Fatal(err)
	}
	if info.Version != 1 || info.DescriptorHash != c.spending.DescriptorHash {
		t.Fatal("setup capability not bound to enrollment")
	}
	var retry bitcoinPaymentPrepared
	body, _ := json.Marshal(request)
	req := httptest.NewRequest("POST", "/v1/vtxo/savings-setup/prepare", bytes.NewReader(body))
	req.Header.Set("Origin", e.svc.ClientOrigin())
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatalf("prepare HTTP %d: %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &retry); err != nil {
		t.Fatal(err)
	}
	if retry.PlanDigest != prepared.PlanDigest {
		t.Fatal("HTTP retry changed the plan")
	}
}

type savingsSetupDeleteOperator struct {
	lightRenewalTestOperator
	deletes                      int
	deleteErr                    error
	deletedProof, deletedMessage string
}

func (o *savingsSetupDeleteOperator) deleteIntent(_ context.Context, proof, message string) error {
	o.deletes++
	o.deletedProof, o.deletedMessage = proof, message
	return o.deleteErr
}

func TestSavingsSetupReleaseRequiresConfirmedExactDeletion(t *testing.T) {
	e, c, prepared, _ := setupFundingFixture(t, "mainnet", "standard")
	session, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	operator := &savingsSetupDeleteOperator{}
	e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	if result, err := e.svc.registerBitcoinPayment(t.Context(), request); err != nil || result.State != "registered" {
		t.Fatalf("register: %+v %v", result, err)
	}
	f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), tree: c.spending.Tree, owner: e.hot}
	deletion := delegatedDeleteFixture(t, f)
	r := bitcoinPaymentReleaseRequest{VaultID: request.VaultID, OperationID: request.OperationID, DeleteIntent: &deletion}
	if result, err := e.svc.releaseBitcoinPayment(t.Context(), r); err != nil || result.State != "waiting_expiry" || operator.deletes != 0 {
		t.Fatalf("early deletion: %+v %v", result, err)
	}
	now := time.Unix(prepared.Plan.RegisterExpireAt+16, 0)
	e.svc.SessionNow = func() time.Time { return now }
	if err := e.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := policy.OpenLedgerForNetwork(e.dbPath, func() time.Time { return now }, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	e.ledger = ledger
	e.svc.Stores = testStores(t, ledger)
	r.DeleteIntent = nil
	if result, err := e.svc.releaseBitcoinPayment(t.Context(), r); err != nil || result.State != "uncertain" || operator.deletes != 0 {
		t.Fatalf("unsigned deletion: %+v %v", result, err)
	}
	// A genuine owner signature for a different input still cannot cancel this one.
	f.plan.Vout++
	wrong := delegatedDeleteFixture(t, f)
	r.DeleteIntent = &wrong
	if _, err := e.svc.releaseBitcoinPayment(t.Context(), r); err == nil || operator.deletes != 0 {
		t.Fatal("wrong input cancellation accepted")
	}
	r.DeleteIntent = &deletion
	operator.deleteErr = fmt.Errorf("delete response lost or no matching intent")
	if result, err := e.svc.releaseBitcoinPayment(t.Context(), r); err != nil || result.State != "uncertain" {
		t.Fatalf("lost delete: %+v %v", result, err)
	}
	used, err := e.ledger.SpentInPeriod(t.Context(), r.VaultID, "")
	if err != nil || used != 1000+prepared.Plan.FeeSats {
		t.Fatalf("uncertain deletion released allowance: %d %v", used, err)
	}
	if err := intent.Verify(operator.deletedProof, operator.deletedMessage, []*btcec.PublicKey{c.spending.Tree.ArkdPub}); err != nil {
		t.Fatalf("delete signatures: %v", err)
	}
	// Restart/retry can use the durable owner proof without another client signature.
	r.DeleteIntent = nil
	operator.deleteErr = nil
	if result, err := e.svc.releaseBitcoinPayment(t.Context(), r); err != nil || result.State != "released" {
		t.Fatalf("confirmed delete: %+v %v", result, err)
	}
	if result, err := e.svc.releaseBitcoinPayment(t.Context(), r); err != nil || result.State != "released" || operator.deletes != 2 {
		t.Fatalf("terminal retry: %+v %v", result, err)
	}
	if used, err := e.ledger.SpentInPeriod(t.Context(), r.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("released allowance: %d %v", used, err)
	}
}

func TestSavingsSetupDeleteCapabilityRejectsOtherMessagesAndOutputs(t *testing.T) {
	e, c, prepared, _ := setupFundingFixture(t, "mainnet", "standard")
	session, _ := btcec.NewPrivateKey()
	registration := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	deletion := delegatedDeleteFixture(t, lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), tree: c.spending.Tree, owner: e.hot})
	for _, bad := range []lightDelegateIntent{
		{Proof: registration.PSBT, Message: registration.Message},
		{Proof: deletion.Proof, Message: `{"type":"delete","expire_at":1}`},
		{Proof: registration.PSBT, Message: deletion.Message},
	} {
		if _, err := e.svc.keys.bitcoinPaymentAuthorization(t.Context(), bitcoinPaymentAuthorization{context: c, plan: prepared.Plan, registrationPSBT: registration.PSBT, registrationMessage: registration.Message, deletion: &bad}); err == nil {
			t.Fatal("invalid cancellation reached signing key")
		}
	}
}

func TestSpendingBitcoinExpiredAbsentIntentReleasesOnlyUndispatchedFinal(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		t.Run(fmt.Sprintf("final-dispatched=%t", dispatched), func(t *testing.T) {
			e, c, prepared, _ := bitcoinFundingFixture(t, "mainnet", "standard", 1)
			session, _ := btcec.NewPrivateKey()
			operatorSession, _ := btcec.NewPrivateKey()
			request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
			operator := &savingsSetupDeleteOperator{deleteErr: stockOperatorIntentAbsent{}}
			operator.finalErr = fmt.Errorf("final response lost")
			e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
			if result, err := e.svc.registerBitcoinPayment(t.Context(), request); err != nil || result.State != "registered" {
				t.Fatalf("register: %+v %v", result, err)
			}
			registration, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
			if err != nil {
				t.Fatal(err)
			}
			f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), descriptor: light.Descriptor{Params: light.Params{Network: c.spending.Binding.Network}}, tree: c.spending.Tree, owner: e.hot}
			_, _, evidence := buildSpendingBatchEvidenceFixture(t, f, registration, session, operatorSession, prepared.Plan.outputs(c)[1:])
			final := lightRenewalFinalRequest{VaultID: request.VaultID, OperationID: request.OperationID, Evidence: evidence}
			if dispatched {
				if result, err := e.svc.finalizeBitcoinPayment(t.Context(), final); err != nil || result.State != "uncertain" {
					t.Fatalf("lost final: %+v %v", result, err)
				}
			}
			now := time.Unix(prepared.Plan.RegisterExpireAt+16, 0)
			e.svc.SessionNow = func() time.Time { return now }
			if err := e.ledger.Close(); err != nil {
				t.Fatal(err)
			}
			ledger, err := policy.OpenLedgerForNetwork(e.dbPath, func() time.Time { return now }, "mainnet")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ledger.Close() })
			if err := ledger.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
				t.Fatal(err)
			}
			e.ledger = ledger
			e.svc.Stores = testStores(t, ledger)
			deletion := delegatedDeleteFixture(t, f)
			r := bitcoinPaymentReleaseRequest{VaultID: request.VaultID, OperationID: request.OperationID, DeleteIntent: &deletion}
			result, err := e.svc.releaseBitcoinPayment(t.Context(), r)
			want := "released"
			if dispatched {
				want = "uncertain"
			}
			if err != nil || result.State != want {
				t.Fatalf("release: %+v %v", result, err)
			}
			used, err := ledger.SpentInPeriod(t.Context(), request.VaultID, "")
			if err != nil || (used == 0) == dispatched {
				t.Fatalf("allowance %d: %v", used, err)
			}
			if dispatched {
				if operator.deletes != 0 {
					t.Fatal("deleted after forfeit dispatch")
				}
				return
			}
			snapshot, err := ledger.GetLightRenewal(t.Context(), r.OperationID)
			if err != nil || snapshot.Events["delete_result"].Outcome != "released" {
				t.Fatalf("absence not retained: %v", err)
			}
			// Even a clock rollback cannot admit the old forfeit after release.
			now = now.Add(-time.Minute)
			if result, err := e.svc.finalizeBitcoinPayment(t.Context(), final); err != nil || result.State != "released" || operator.finals != 0 {
				t.Fatalf("released batch reopened: %+v %v", result, err)
			}
			r.DeleteIntent = nil
			if result, err := e.svc.releaseBitcoinPayment(t.Context(), r); err != nil || result.State != "released" || operator.deletes != 1 {
				t.Fatalf("release retry: %+v %v", result, err)
			}
		})
	}
}

func TestSpendingBitcoinLostFinalCannotReleaseOrSubmitTwice(t *testing.T) {
	e, c, prepared, _ := bitcoinFundingFixture(t, "mainnet", "standard", 1)
	session, _ := btcec.NewPrivateKey()
	operatorSession, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	operator := &lightRenewalTestOperator{finalErr: fmt.Errorf("response lost")}
	e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	result, err := e.svc.registerBitcoinPayment(t.Context(), request)
	if err != nil || result.State != "registered" {
		t.Fatalf("register: %+v %v", result, err)
	}
	registration, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
	if err != nil {
		t.Fatal(err)
	}
	f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), descriptor: light.Descriptor{Params: light.Params{Network: c.spending.Binding.Network}}, tree: c.spending.Tree, owner: e.hot}
	_, _, evidence := buildSpendingBatchEvidenceFixture(t, f, registration, session, operatorSession, prepared.Plan.outputs(c)[1:])
	final := lightRenewalFinalRequest{VaultID: request.VaultID, OperationID: request.OperationID, Evidence: evidence}
	for i := 0; i < 2; i++ {
		result, err = e.svc.finalizeBitcoinPayment(t.Context(), final)
		if err != nil || result.State != "uncertain" {
			t.Fatalf("final: %+v %v", result, err)
		}
	}
	if operator.finals != 1 {
		t.Fatalf("dispatched %d times", operator.finals)
	}
	result, err = e.svc.releaseBitcoinPayment(t.Context(), bitcoinPaymentReleaseRequest{VaultID: request.VaultID, OperationID: request.OperationID})
	if err != nil || result.State != "uncertain" {
		t.Fatalf("unsafe release: %+v %v", result, err)
	}
	used, err := e.ledger.SpentInPeriod(t.Context(), request.VaultID, "")
	if err != nil || used != 1500+prepared.Plan.FeeSats {
		t.Fatalf("lost final allowance: %d %v", used, err)
	}
}
