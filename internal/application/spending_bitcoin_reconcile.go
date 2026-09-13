package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
)

func (s *Service) reconcileBitcoinPayment(ctx context.Context, r spendingRenewalOperationRequest) (spendingRenewalResponse, error) {
	// An absent operation is useful only to a client holding an expired, signed
	// prepare request. It never proves that a dispatched transaction failed.
	if _, err := s.bitcoinPaymentContext(r.VaultID); err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return spendingRenewalResponse{}, err
	}
	prior, err := s.Stores.LightRenewal.GetLightRenewal(ctx, r.OperationID)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if prior == nil {
		return spendingRenewalResponse{State: "not_found"}, nil
	}
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return spendingRenewalResponse{State: "released"}, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; !ok {
		// delete_result means the queue was cleared; its "released" outcome
		// does not mean the input/allowance release was committed. Complete the
		// live-input check and durable release before exposing that state.
		if _, deleted := snapshot.Events["delete_result"]; deleted {
			return s.releaseBitcoinPayment(ctx, bitcoinPaymentReleaseRequest{VaultID: r.VaultID, OperationID: r.OperationID})
		}
		return spendingRenewalResponse{State: spendingRenewalState(snapshot), IntentID: snapshot.Events["register_result"].OperatorRef}, nil
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	registration, err := bitcoinPaymentStoredRegistration(snapshot, p, c)
	if err != nil {
		release()
		return spendingRenewalResponse{}, err
	}
	var evidence spendingRenewalFinalEvidence
	if err := json.Unmarshal([]byte(snapshot.Events["final_authorized"].Evidence), &evidence); err != nil {
		release()
		return spendingRenewalResponse{}, err
	}
	final, err := verifyBitcoinPaymentFinal(evidence, p, c, registration)
	release()
	if err != nil || hex.EncodeToString(final.RequestDigest) != snapshot.Events["final_dispatched"].RequestDigest {
		return spendingRenewalResponse{}, fmt.Errorf("Bitcoin payment persisted final mismatch")
	}
	response := spendingRenewalResponse{State: "uncertain", CommitmentTxid: final.CommitmentTxid, ReceiverTxid: final.ReceiverTxid, ReceiverVout: final.ReceiverVout}
	if _, ok := snapshot.Events["final_result"]; ok {
		response.State = "submitted"
	}
	if _, ok := snapshot.Events["confirmed"]; ok {
		response.State = "confirmed"
		return response, nil
	}
	indexer, ok := s.ArkResolver.(spendingRenewalIndexer)
	if !ok {
		return spendingRenewalResponse{}, fmt.Errorf("Bitcoin payment reconciliation unavailable")
	}
	settled, err := indexer.spendingRenewalSettled(ctx, p.batchInput(), final, c.spending.Tree.PkScript)
	if err != nil {
		return response, err
	}
	if !settled {
		released, err := s.releaseEndedBitcoinPayment(ctx, snapshot, p, c, final)
		if err != nil {
			return response, err
		}
		if released {
			return spendingRenewalResponse{State: "released"}, nil
		}
		released, err = s.releaseConflictedBitcoinPayment(ctx, snapshot, p, c, evidence, final)
		if err != nil {
			return response, err
		}
		if released {
			return spendingRenewalResponse{State: "released"}, nil
		}
		return response, nil
	}
	// A projected VTXO alone is insufficient: independently check the exact
	// Bitcoin commitment output backing the signed replacement tree.
	chain, err := s.spendingRenewalChain()
	if err != nil {
		return response, err
	}
	confirmed, err := chain.confirmedOutpoint(ctx, final.CommitmentTxid, 0)
	if err != nil {
		return response, nil
	}
	packet, err := parseCanonicalVaultBoardPSBT(evidence.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || confirmed.ValueSats != packet.UnsignedTx.TxOut[0].Value || !bytes.Equal(confirmed.PkScript, packet.UnsignedTx.TxOut[0].PkScript) {
		return response, fmt.Errorf("Bitcoin payment commitment mismatch")
	}
	proof, err := json.Marshal(struct {
		Commitment string `json:"commitmentTxid"`
		Block      string `json:"blockHash"`
		Height     int64  `json:"blockHeight"`
		Receiver   string `json:"receiverTxid"`
		Vout       uint32 `json:"receiverVout"`
	}{final.CommitmentTxid, confirmed.FundingBlockHash, confirmed.FundingBlockHeight, final.ReceiverTxid, final.ReceiverVout})
	if err != nil {
		return response, err
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "confirmed", RequestDigest: hex.EncodeToString(final.RequestDigest), Outcome: "confirmed", OperatorRef: final.CommitmentTxid, Evidence: string(proof)}); err != nil {
		return response, err
	}
	response.State = "confirmed"
	return response, nil
}

type bitcoinPaymentReleaseRequest struct {
	VaultID      string                  `json:"vaultId"`
	OperationID  string                  `json:"operationId"`
	DeleteIntent *spendingDelegateIntent `json:"deleteIntent,omitempty"`
}

func (s *Service) releaseBitcoinPayment(ctx context.Context, r bitcoinPaymentReleaseRequest) (spendingRenewalResponse, error) {
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return spendingRenewalResponse{State: "released"}, nil
	}
	if _, ok := snapshot.Events["cancelled"]; ok {
		return spendingRenewalResponse{State: "cancelled"}, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; ok {
		return spendingRenewalResponse{State: "uncertain"}, nil
	}
	// No cosignature leaves this process before the durable final-dispatch CAS.
	// Fence even a prepared final after expiry if it never reached that boundary.
	// A racing dispatcher will fail its CAS before contacting the Operator.
	phase := "cancelled"
	digest := snapshot.Operation.PlanDigest
	proof := ""
	if dispatch, ok := snapshot.Events["register_dispatched"]; ok {
		if s.vtxoNow().Before(time.Unix(p.RegisterExpireAt, 0).Add(15 * time.Second)) {
			return spendingRenewalResponse{State: "waiting_expiry"}, nil
		}
		// Registration expiry does not remove the Operator's queued intent.
		// Require deletion or an exact, verified absence response for the owner proof.
		cleared, err := s.deleteBitcoinPaymentIntent(ctx, snapshot, p, c, r.DeleteIntent)
		if err != nil {
			return spendingRenewalResponse{}, err
		}
		if !cleared {
			return spendingRenewalResponse{State: "uncertain"}, nil
		}
		input, err := s.liveRenewalInput(ctx, c.spending.Tree, p.Txid, p.Vout)
		if err != nil || input.ValueSats != uint64(p.ValueSats) {
			return spendingRenewalResponse{State: "uncertain"}, nil
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			return spendingRenewalResponse{}, err
		}
		phase = "released"
		digest = dispatch.RequestDigest
		proof = string(encoded)
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: phase, RequestDigest: digest, Evidence: proof}); err != nil {
		return spendingRenewalResponse{}, err
	}
	return spendingRenewalResponse{State: phase}, nil
}

// Cancellation is non-monetary and may be retried from its durable evidence.
// An exact stock no-match response proves queue absence, not batch failure.
// For this path only, expiry and the durable no-final-dispatch fence prevent
// the old batch from acquiring its missing forfeit cosignature. The caller
// additionally checks that the original input is still live before release.
func (s *Service) deleteBitcoinPaymentIntent(ctx context.Context, snapshot *policy.LightRenewalSnapshot, p bitcoinPaymentPlan, c bitcoinPaymentContext, supplied *spendingDelegateIntent) (bool, error) {
	if _, ok := snapshot.Events["delete_result"]; ok {
		return true, nil
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return false, err
	}
	registration, err := bitcoinPaymentStoredRegistration(snapshot, p, c)
	if err != nil {
		release()
		return false, err
	}
	var deletion spendingDelegateIntent
	if saved, ok := snapshot.Events["delete_authorized"]; ok {
		if err := json.Unmarshal([]byte(saved.Evidence), &deletion); err != nil {
			release()
			return false, err
		}
	} else if supplied != nil {
		deletion = *supplied
	} else {
		release()
		return false, nil
	}
	if err := verifyRenewalDelete(deletion, p.batchInput(), c.spending); err != nil {
		release()
		return false, err
	}
	encoded, err := json.Marshal(deletion)
	release()
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(append([]byte("vaulted-vtxo/savings-setup/delete/v1:"), encoded...))
	digest := hex.EncodeToString(sum[:])
	if saved, ok := snapshot.Events["delete_authorized"]; ok && saved.RequestDigest != digest {
		return false, fmt.Errorf("Bitcoin payment cancellation changed")
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: p.OperationID, Phase: "delete_authorized", RequestDigest: digest, Evidence: string(encoded)}); err != nil {
		return false, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return false, err
	}
	signed, err := s.keys.bitcoinPaymentAuthorization(ctx, bitcoinPaymentAuthorization{context: c, plan: p, registrationPSBT: registration.CanonicalPSBT, registrationMessage: registration.Message, deletion: &deletion})
	release()
	if err != nil {
		return false, err
	}
	operator, err := s.dialLightRenewalOperator(ctx)
	if err != nil {
		return false, err
	}
	deleter, ok := operator.(interface {
		deleteIntent(context.Context, string, string) error
	})
	if !ok {
		return false, fmt.Errorf("Bitcoin payment cancellation unavailable")
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: p.OperationID, Phase: "delete_dispatched", RequestDigest: digest}); err != nil {
		return false, err
	}
	if err := deleter.deleteIntent(ctx, signed, deletion.Message); err != nil {
		if _, absent := err.(stockOperatorIntentAbsent); !absent {
			return false, nil
		}
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: p.OperationID, Phase: "delete_result", RequestDigest: digest, Outcome: "released"}); err != nil {
		return false, err
	}
	return true, nil
}
