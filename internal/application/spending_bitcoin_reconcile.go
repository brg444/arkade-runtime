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

func (s *Service) reconcileBitcoinPayment(ctx context.Context, r lightRenewalOperationRequest) (lightRenewalResponse, error) {
	// An absent operation is useful only to a client holding an expired, signed
	// prepare request. It never proves that a dispatched transaction failed.
	if _, err := s.bitcoinPaymentContext(r.VaultID, true); err != nil {
		return lightRenewalResponse{}, err
	}
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return lightRenewalResponse{}, err
	}
	prior, err := s.Stores.LightRenewal.GetLightRenewal(ctx, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if prior == nil {
		return lightRenewalResponse{State: "not_found"}, nil
	}
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return lightRenewalResponse{State: "released"}, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; !ok {
		return lightRenewalResponse{State: lightRenewalState(snapshot), IntentID: snapshot.Events["register_result"].OperatorRef}, nil
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	registration, err := bitcoinPaymentStoredRegistration(snapshot, p, c)
	if err != nil {
		release()
		return lightRenewalResponse{}, err
	}
	var evidence lightRenewalFinalEvidence
	if err := json.Unmarshal([]byte(snapshot.Events["final_authorized"].Evidence), &evidence); err != nil {
		release()
		return lightRenewalResponse{}, err
	}
	final, err := verifyBitcoinPaymentFinal(evidence, p, c, registration)
	release()
	if err != nil || hex.EncodeToString(final.RequestDigest) != snapshot.Events["final_dispatched"].RequestDigest {
		return lightRenewalResponse{}, fmt.Errorf("Savings setup persisted final mismatch")
	}
	response := lightRenewalResponse{State: "uncertain", CommitmentTxid: final.CommitmentTxid, ReceiverTxid: final.ReceiverTxid, ReceiverVout: final.ReceiverVout}
	if _, ok := snapshot.Events["final_result"]; ok {
		response.State = "submitted"
	}
	if _, ok := snapshot.Events["confirmed"]; ok {
		response.State = "confirmed"
		return response, nil
	}
	indexer, ok := s.ArkResolver.(lightRenewalIndexer)
	if !ok {
		return lightRenewalResponse{}, fmt.Errorf("Savings setup reconciliation unavailable")
	}
	settled, err := indexer.lightRenewalSettled(ctx, p.batchInput(), final, c.spending.Tree.PkScript)
	if err != nil {
		return response, err
	}
	if !settled {
		released, err := s.releaseConflictedBitcoinPayment(ctx, snapshot, p, c, evidence, final)
		if err != nil {
			return response, err
		}
		if released {
			return lightRenewalResponse{State: "released"}, nil
		}
		return response, nil
	}
	// A projected VTXO alone is insufficient: independently check the exact
	// Bitcoin commitment output backing the signed replacement tree.
	chain, err := s.lightRenewalChain()
	if err != nil {
		return response, err
	}
	confirmed, err := chain.confirmedOutpoint(ctx, final.CommitmentTxid, 0)
	if err != nil {
		return response, nil
	}
	packet, err := parseCanonicalVaultBoardPSBT(evidence.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || confirmed.ValueSats != packet.UnsignedTx.TxOut[0].Value || !bytes.Equal(confirmed.PkScript, packet.UnsignedTx.TxOut[0].PkScript) {
		return response, fmt.Errorf("Savings setup Bitcoin commitment mismatch")
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
	VaultID      string               `json:"vaultId"`
	OperationID  string               `json:"operationId"`
	DeleteIntent *lightDelegateIntent `json:"deleteIntent,omitempty"`
}

func (s *Service) releaseBitcoinPayment(ctx context.Context, r bitcoinPaymentReleaseRequest) (lightRenewalResponse, error) {
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return lightRenewalResponse{State: "released"}, nil
	}
	if _, ok := snapshot.Events["cancelled"]; ok {
		return lightRenewalResponse{State: "cancelled"}, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; ok {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	// No cosignature leaves this process before the durable final-dispatch CAS.
	// Fence even a prepared final after expiry if it never reached that boundary.
	// A racing dispatcher will fail its CAS before contacting the Operator.
	phase := "cancelled"
	digest := snapshot.Operation.PlanDigest
	proof := ""
	if dispatch, ok := snapshot.Events["register_dispatched"]; ok {
		if s.vtxoNow().Before(time.Unix(p.RegisterExpireAt, 0).Add(15 * time.Second)) {
			return lightRenewalResponse{State: "waiting_expiry"}, nil
		}
		// Registration expiry does not remove the Operator's queued intent.
		// Require deletion or an exact, verified absence response for the owner proof.
		cleared, err := s.deleteBitcoinPaymentIntent(ctx, snapshot, p, c, r.DeleteIntent)
		if err != nil {
			return lightRenewalResponse{}, err
		}
		if !cleared {
			return lightRenewalResponse{State: "uncertain"}, nil
		}
		input, err := s.liveRenewalInput(ctx, c.spending.Tree, p.Txid, p.Vout)
		if err != nil || input.ValueSats != uint64(p.ValueSats) {
			return lightRenewalResponse{State: "uncertain"}, nil
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			return lightRenewalResponse{}, err
		}
		phase = "released"
		digest = dispatch.RequestDigest
		proof = string(encoded)
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: phase, RequestDigest: digest, Evidence: proof}); err != nil {
		return lightRenewalResponse{}, err
	}
	return lightRenewalResponse{State: phase}, nil
}

// Cancellation is non-monetary and may be retried from its durable evidence.
// An exact stock no-match response proves queue absence, not batch failure.
// For this path only, expiry and the durable no-final-dispatch fence prevent
// the old batch from acquiring its missing forfeit cosignature. The caller
// additionally checks that the original input is still live before release.
func (s *Service) deleteBitcoinPaymentIntent(ctx context.Context, snapshot *policy.LightRenewalSnapshot, p bitcoinPaymentPlan, c bitcoinPaymentContext, supplied *lightDelegateIntent) (bool, error) {
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
	var deletion lightDelegateIntent
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
		return false, fmt.Errorf("Savings setup cancellation changed")
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
		return false, fmt.Errorf("Savings setup cancellation unavailable")
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
