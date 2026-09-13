package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/brg444/arkade-runtime/internal/policy"
)

func (s *Service) loadBitcoinPayment(ctx context.Context, vault, id string) (*policy.SpendingRenewalSnapshot, bitcoinPaymentPlan, bitcoinPaymentContext, error) {
	c, err := s.bitcoinPaymentContext(vault)
	if err != nil {
		return nil, bitcoinPaymentPlan{}, c, err
	}
	if _, err := canonicalVtxoOperationID(id); err != nil {
		return nil, bitcoinPaymentPlan{}, c, err
	}
	snapshot, err := s.Stores.SpendingRenewal.GetSpendingRenewal(ctx, id)
	if err != nil || snapshot == nil || snapshot.Operation.VaultID != vault {
		return nil, bitcoinPaymentPlan{}, c, fmt.Errorf("Bitcoin payment operation unavailable")
	}
	prepared, err := bitcoinPaymentSnapshot(snapshot, c)
	return snapshot, prepared.Plan, c, err
}
func (s *Service) registerBitcoinPayment(ctx context.Context, r spendingRenewalRegisterRequest) (spendingRenewalResponse, error) {
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return spendingRenewalResponse{State: "released"}, nil
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	verified, err := verifyBitcoinPaymentRegistration(r.PSBT, r.Message, p, c)
	release()
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	credential, count, err := s.verifyVtxoAuthorization(ctx, r.VaultID, verified.PlanDigest, r.Assertion, r.DirectSig)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	requestDigest := hex.EncodeToString(verified.RequestDigest)
	if prior, ok := snapshot.Events["register_authorized"]; ok && prior.RequestDigest != requestDigest {
		return spendingRenewalResponse{}, fmt.Errorf("Bitcoin payment registration changed")
	}
	for _, phase := range []string{"confirmed", "released", "cancelled", "final_result", "final_dispatched", "final_authorized"} {
		if _, ok := snapshot.Events[phase]; ok {
			return spendingRenewalResponse{State: spendingRenewalState(snapshot)}, nil
		}
	}
	if result, ok := snapshot.Events["register_result"]; ok {
		return spendingRenewalResponse{State: result.Outcome, IntentID: result.OperatorRef}, nil
	}
	if _, ok := snapshot.Events["register_dispatched"]; ok {
		return spendingRenewalResponse{State: "uncertain"}, nil
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return spendingRenewalResponse{}, err
	}
	evidence, err := json.Marshal(spendingRenewalRegistrationEvidence{verified.CanonicalPSBT, verified.Message})
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, _, err := s.Stores.SpendingRenewal.AppendSpendingRenewalEvent(ctx, policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "register_authorized", RequestDigest: requestDigest, Evidence: string(evidence)}, credential, count); err != nil {
		return spendingRenewalResponse{}, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	signed, err := s.keys.bitcoinPaymentAuthorization(ctx, bitcoinPaymentAuthorization{context: c, plan: p, registrationPSBT: verified.CanonicalPSBT, registrationMessage: verified.Message})
	release()
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	operator, err := s.dialSpendingRenewalOperator(ctx)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return spendingRenewalResponse{}, err
	}
	_, created, err := s.Stores.SpendingRenewal.AppendSpendingRenewalEvent(ctx, policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "register_dispatched", RequestDigest: requestDigest}, nil, 0)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if !created {
		return spendingRenewalResponse{State: "uncertain"}, nil
	}
	intent, err := operator.registerIntent(ctx, signed, verified.Message)
	if err != nil {
		if isDefiniteVaultBoardRegisterRejection(err) {
			if persistErr := s.persistSpendingRenewalEvent(policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "register_result", RequestDigest: requestDigest, Outcome: "rejected"}); persistErr == nil {
				log.Printf("Bitcoin payment registration rejected: %s", err.Error())
				return spendingRenewalResponse{State: "rejected", Reason: err.Error()}, nil
			}
		}
		return spendingRenewalResponse{State: "uncertain"}, nil
	}
	if err := s.persistSpendingRenewalEvent(policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "register_result", RequestDigest: requestDigest, Outcome: "registered", OperatorRef: intent}); err != nil {
		return spendingRenewalResponse{State: "uncertain"}, nil
	}
	return spendingRenewalResponse{State: "registered", IntentID: intent}, nil
}
func bitcoinPaymentStoredRegistration(snapshot *policy.SpendingRenewalSnapshot, p bitcoinPaymentPlan, c bitcoinPaymentContext) (verifiedSpendingRenewalRegistration, error) {
	event, ok := snapshot.Events["register_authorized"]
	if !ok {
		return verifiedSpendingRenewalRegistration{}, fmt.Errorf("Bitcoin payment registration missing")
	}
	var evidence spendingRenewalRegistrationEvidence
	if err := json.Unmarshal([]byte(event.Evidence), &evidence); err != nil {
		return verifiedSpendingRenewalRegistration{}, err
	}
	verified, err := verifyBitcoinPaymentRegistration(evidence.PSBT, evidence.Message, p, c)
	if err != nil || hex.EncodeToString(verified.RequestDigest) != event.RequestDigest {
		return verifiedSpendingRenewalRegistration{}, fmt.Errorf("Bitcoin payment registration evidence changed")
	}
	return verified, nil
}
func (s *Service) finalizeBitcoinPayment(ctx context.Context, r spendingRenewalFinalRequest) (spendingRenewalResponse, error) {
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return spendingRenewalResponse{State: "released"}, nil
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
	verified, err := verifyBitcoinPaymentFinal(r.Evidence, p, c, registration)
	release()
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	digest := hex.EncodeToString(verified.RequestDigest)
	response := spendingRenewalResponse{CommitmentTxid: verified.CommitmentTxid, ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout}
	if previous, ok := snapshot.Events["final_authorized"]; ok && previous.RequestDigest != digest {
		return spendingRenewalResponse{}, fmt.Errorf("Bitcoin payment final request changed")
	}
	if _, ok := snapshot.Events["confirmed"]; ok {
		response.State = "confirmed"
		return response, nil
	}
	if _, ok := snapshot.Events["final_result"]; ok {
		response.State = "submitted"
		return response, nil
	}
	if _, ok := snapshot.Events["final_dispatched"]; ok {
		response.State = "uncertain"
		return response, nil
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return spendingRenewalResponse{}, err
	}
	operator, err := s.dialSpendingRenewalOperator(ctx)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	// Final evidence can arrive after the Operator has already closed a failed
	// batch. Fence that case before signing or persisting dispatch authority.
	if err := operator.requireUnendedCommitment(ctx, verified.CommitmentTxid); err != nil {
		return spendingRenewalResponse{}, err
	}
	raw, err := json.Marshal(r.Evidence)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if _, _, err := s.Stores.SpendingRenewal.AppendSpendingRenewalEvent(ctx, policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "final_authorized", RequestDigest: digest, Evidence: string(raw)}, nil, 0); err != nil {
		return spendingRenewalResponse{}, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	signed, err := s.keys.bitcoinPaymentAuthorization(ctx, bitcoinPaymentAuthorization{context: c, plan: p, registrationPSBT: registration.CanonicalPSBT, registrationMessage: registration.Message, final: &r.Evidence})
	release()
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return spendingRenewalResponse{}, err
	}
	// Signing and the live-input check may outlast the batch. Recheck at the
	// final boundary so an ended batch cannot create a durable reservation.
	if err := operator.requireUnendedCommitment(ctx, verified.CommitmentTxid); err != nil {
		return spendingRenewalResponse{}, err
	}
	_, created, err := s.Stores.SpendingRenewal.AppendSpendingRenewalEvent(ctx, policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "final_dispatched", RequestDigest: digest}, nil, 0)
	if err != nil {
		return spendingRenewalResponse{}, err
	}
	if !created {
		response.State = "uncertain"
		return response, nil
	}
	if err := operator.submitLightForfeit(ctx, signed); err != nil {
		response.State = "uncertain"
		return response, nil
	}
	if err := s.persistSpendingRenewalEvent(policy.SpendingRenewalEvent{OperationID: r.OperationID, Phase: "final_result", RequestDigest: digest, Outcome: "submitted"}); err != nil {
		response.State = "uncertain"
		return response, nil
	}
	response.State = "submitted"
	return response, nil
}
