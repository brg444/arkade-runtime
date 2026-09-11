package application

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
)

// Keep proof construction in the test; the fake chain cannot supply keys or
// alter the authenticated transaction retained by the service.
type bitcoinConflictProofChain struct {
	vaultBoardTestChain
	proof *policy.BitcoinConflictEvidence
}

func (c *bitcoinConflictProofChain) confirmedBitcoinConflict(context.Context, string, *wire.MsgTx) (*policy.BitcoinConflictEvidence, error) {
	return c.proof, nil
}

func TestBitcoinConflictReleasesLostFinalWithoutSigningAgain(t *testing.T) {
	for _, kind := range []string{"legacy", "canonical"} {
		t.Run(kind, func(t *testing.T) {
			var e *env
			var c bitcoinPaymentContext
			var prepared bitcoinPaymentPrepared
			if kind == "legacy" {
				e, c, prepared, _ = setupFundingFixture(t, "mainnet", "standard")
			} else {
				e, c, prepared, _ = bitcoinFundingFixture(t, "mainnet", "standard", 1)
			}
			session, _ := btcec.NewPrivateKey()
			operatorSession, _ := btcec.NewPrivateKey()
			request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
			operator := &lightRenewalTestOperator{finalErr: fmt.Errorf("response lost")}
			e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
			if result, err := e.svc.registerBitcoinPayment(t.Context(), request); err != nil || result.State != "registered" {
				t.Fatalf("register %+v %v", result, err)
			}
			registration, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
			if err != nil {
				t.Fatal(err)
			}
			f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), descriptor: light.Descriptor{Params: light.Params{Network: c.spending.Binding.Network}}, tree: c.spending.Tree, owner: e.hot}
			_, _, evidence := buildSpendingBatchEvidenceFixture(t, f, registration, session, operatorSession, prepared.Plan.outputs(c)[1:])
			final := lightRenewalFinalRequest{VaultID: request.VaultID, OperationID: request.OperationID, Evidence: evidence}
			if result, err := e.svc.finalizeBitcoinPayment(t.Context(), final); err != nil || result.State != "uncertain" {
				t.Fatalf("final %+v %v", result, err)
			}
			e.svc.ArkResolver = &lightRenewalSettledResolver{stubArkResolver: e.svc.ArkResolver.(stubArkResolver)}
			packet, err := parsePSBT(evidence.CommitmentPSBT)
			if err != nil {
				t.Fatal(err)
			}
			proof := conflictFixture(t, packet.UnsignedTx)
			chain := &bitcoinConflictProofChain{}
			e.svc.vaultBoardRuntime = &vaultBoardRuntime{chain: chain}
			op := lightRenewalOperationRequest{VaultID: request.VaultID, OperationID: request.OperationID}
			if result, err := e.svc.reconcileBitcoinPayment(t.Context(), op); err != nil || result.State != "uncertain" {
				t.Fatalf("no conflict %+v %v", result, err)
			}
			shallow := proof
			shallow.TipHeight--
			chain.proof = &shallow
			if _, err := e.svc.reconcileBitcoinPayment(t.Context(), op); err == nil {
				t.Fatal("shallow proof released")
			}
			chain.proof = &proof
			resolver := e.svc.ArkResolver.(*lightRenewalSettledResolver)
			coins := resolver.vtxos
			resolver.vtxos = nil
			if result, err := e.svc.reconcileBitcoinPayment(t.Context(), op); err != nil || result.State != "uncertain" {
				t.Fatalf("missing original input: %+v %v", result, err)
			}
			resolver.vtxos = coins
			// Restart the ledger before reconciliation, proving that the original signed
			// transcript alone is sufficient after the foreground request was lost.
			now := e.svc.vtxoNow()
			if err := e.ledger.Close(); err != nil {
				t.Fatal(err)
			}
			ledger, err := policy.OpenLedgerForNetwork(e.dbPath, func() time.Time { return now }, "mainnet")
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			if err := ledger.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
				t.Fatal(err)
			}
			e.ledger = ledger
			e.svc.Stores = testStores(t, ledger)
			for i := 0; i < 2; i++ {
				if result, err := e.svc.reconcileBitcoinPayment(t.Context(), op); err != nil || result.State != "released" {
					t.Fatalf("reconcile %+v %v", result, err)
				}
				if result, err := e.svc.finalizeBitcoinPayment(t.Context(), final); err != nil || result.State != "released" {
					t.Fatalf("final replay %+v %v", result, err)
				}
			}
			if operator.finals != 1 {
				t.Fatalf("signed again %d", operator.finals)
			}
			if used, err := ledger.SpentInPeriod(t.Context(), request.VaultID, ""); err != nil || used != 0 {
				t.Fatalf("allowance %d %v", used, err)
			}
			saved, err := ledger.GetLightRenewal(t.Context(), request.OperationID)
			if err != nil || saved.Events["released"].Evidence == "" || saved.Events["final_dispatched"].Phase == "" {
				t.Fatalf("missing retained evidence: %v", err)
			}
		})
	}
}

func TestEndedOperatorBatchReleasesLateFinalWithLiveInput(t *testing.T) {
	e, c, prepared, _ := bitcoinFundingFixture(t, "mainnet", "standard", 1)
	session, _ := btcec.NewPrivateKey()
	operatorSession, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	operator := &lightRenewalTestOperator{finalErr: fmt.Errorf("Operator rejected final after batch ended")}
	e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	if result, err := e.svc.registerBitcoinPayment(t.Context(), request); err != nil || result.State != "registered" {
		t.Fatalf("register %+v %v", result, err)
	}
	registration, err := verifyBitcoinPaymentRegistration(request.PSBT, request.Message, prepared.Plan, c)
	if err != nil {
		t.Fatal(err)
	}
	f := lightRenewalProofFixture{env: e, plan: prepared.Plan.batchInput(), descriptor: light.Descriptor{Params: light.Params{Network: c.spending.Binding.Network}}, tree: c.spending.Tree, owner: e.hot}
	_, _, evidence := buildSpendingBatchEvidenceFixture(t, f, registration, session, operatorSession, prepared.Plan.outputs(c)[1:])
	final := lightRenewalFinalRequest{VaultID: request.VaultID, OperationID: request.OperationID, Evidence: evidence}
	if result, err := e.svc.finalizeBitcoinPayment(t.Context(), final); err != nil || result.State != "uncertain" {
		t.Fatalf("final %+v %v", result, err)
	}
	snapshot, err := e.ledger.GetLightRenewal(t.Context(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	dispatchedAt, err := time.Parse(time.RFC3339, snapshot.Events["final_dispatched"].CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.ArkResolver = &lightRenewalSettledResolver{stubArkResolver: e.svc.ArkResolver.(stubArkResolver)}
	e.svc.vaultBoardRuntime = &vaultBoardRuntime{chain: &bitcoinConflictProofChain{}}
	op := lightRenewalOperationRequest{VaultID: request.VaultID, OperationID: request.OperationID}
	operator.endedAt = dispatchedAt.Unix()
	if result, err := e.svc.reconcileBitcoinPayment(t.Context(), op); err != nil || result.State != "uncertain" {
		t.Fatalf("ambiguous ordering %+v %v", result, err)
	}
	operator.endedAt--
	for i := 0; i < 2; i++ {
		if result, err := e.svc.reconcileBitcoinPayment(t.Context(), op); err != nil || result.State != "released" {
			t.Fatalf("ended batch release %+v %v", result, err)
		}
	}
	if operator.finals != 1 || operator.endedQueries != 2 {
		t.Fatalf("unexpected Operator calls finals=%d status=%d", operator.finals, operator.endedQueries)
	}
	if used, err := e.ledger.SpentInPeriod(t.Context(), request.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("allowance %d %v", used, err)
	}
	snapshot, err = e.ledger.GetLightRenewal(t.Context(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	var proof policy.BitcoinEndedBatchEvidence
	if err := json.Unmarshal([]byte(snapshot.Events["released"].Evidence), &proof); err != nil || proof.Kind != policy.BitcoinEndedBatchKind || proof.CommitmentTxid == "" {
		t.Fatalf("release evidence %+v %v", proof, err)
	}
}
