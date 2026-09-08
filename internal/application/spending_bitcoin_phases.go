package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/brg444/arkade-runtime/internal/policy"
)

func (s *Service) loadBitcoinPayment(ctx context.Context, vault, id string) (*policy.LightRenewalSnapshot, bitcoinPaymentPlan, bitcoinPaymentContext, error) {
	c, err := s.bitcoinPaymentContext(vault, true)
	if err != nil {
		return nil, bitcoinPaymentPlan{}, c, err
	}
	if _, err := canonicalVtxoOperationID(id); err != nil {
		return nil, bitcoinPaymentPlan{}, c, err
	}
	snapshot, err := s.Stores.LightRenewal.GetLightRenewal(ctx, id)
	if err != nil || snapshot == nil || snapshot.Operation.VaultID != vault {
		return nil, bitcoinPaymentPlan{}, c, fmt.Errorf("Savings setup operation unavailable")
	}
	if snapshot.Operation.Kind == policy.SavingsSetupBatchKind {
		c, err = s.bitcoinPaymentContext(vault)
		if err != nil {
			return nil, bitcoinPaymentPlan{}, c, err
		}
	}
	prepared, err := bitcoinPaymentSnapshot(snapshot, c)
	return snapshot, prepared.Plan, c, err
}
func (s *Service) registerBitcoinPayment(ctx context.Context, r lightRenewalRegisterRequest) (lightRenewalResponse, error) {
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return lightRenewalResponse{State: "released"}, nil
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	verified, err := verifyBitcoinPaymentRegistration(r.PSBT, r.Message, p, c)
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	credential, count, err := s.verifyVtxoAuthorization(ctx, r.VaultID, verified.PlanDigest, r.Assertion, r.DirectSig)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	requestDigest := hex.EncodeToString(verified.RequestDigest)
	if prior, ok := snapshot.Events["register_authorized"]; ok && prior.RequestDigest != requestDigest {
		return lightRenewalResponse{}, fmt.Errorf("Savings setup registration changed")
	}
	for _, phase := range []string{"confirmed", "released", "cancelled", "final_result", "final_dispatched", "final_authorized"} {
		if _, ok := snapshot.Events[phase]; ok {
			return lightRenewalResponse{State: lightRenewalState(snapshot)}, nil
		}
	}
	if result, ok := snapshot.Events["register_result"]; ok {
		return lightRenewalResponse{State: result.Outcome, IntentID: result.OperatorRef}, nil
	}
	if _, ok := snapshot.Events["register_dispatched"]; ok {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return lightRenewalResponse{}, err
	}
	evidence, err := json.Marshal(lightRenewalRegistrationEvidence{verified.CanonicalPSBT, verified.Message})
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, _, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_authorized", RequestDigest: requestDigest, Evidence: string(evidence)}, credential, count); err != nil {
		return lightRenewalResponse{}, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	signed, err := s.keys.bitcoinPaymentAuthorization(ctx, bitcoinPaymentAuthorization{context: c, plan: p, registrationPSBT: verified.CanonicalPSBT, registrationMessage: verified.Message})
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	operator, err := s.dialLightRenewalOperator(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return lightRenewalResponse{}, err
	}
	_, created, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_dispatched", RequestDigest: requestDigest}, nil, 0)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if !created {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	intent, err := operator.registerIntent(ctx, signed, verified.Message)
	if err != nil {
		if isDefiniteVaultBoardRegisterRejection(err) {
			if persistErr := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_result", RequestDigest: requestDigest, Outcome: "rejected"}); persistErr == nil {
				log.Printf("Bitcoin payment registration rejected: %s", err.Error())
				return lightRenewalResponse{State: "rejected", Reason: err.Error()}, nil
			}
		}
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "register_result", RequestDigest: requestDigest, Outcome: "registered", OperatorRef: intent}); err != nil {
		return lightRenewalResponse{State: "uncertain"}, nil
	}
	return lightRenewalResponse{State: "registered", IntentID: intent}, nil
}
func bitcoinPaymentStoredRegistration(snapshot *policy.LightRenewalSnapshot, p bitcoinPaymentPlan, c bitcoinPaymentContext) (verifiedLightRenewalRegistration, error) {
	event, ok := snapshot.Events["register_authorized"]
	if !ok {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Savings setup registration missing")
	}
	var evidence lightRenewalRegistrationEvidence
	if err := json.Unmarshal([]byte(event.Evidence), &evidence); err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	verified, err := verifyBitcoinPaymentRegistration(evidence.PSBT, evidence.Message, p, c)
	if err != nil || hex.EncodeToString(verified.RequestDigest) != event.RequestDigest {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Savings setup registration evidence changed")
	}
	return verified, nil
}
func (s *Service) finalizeBitcoinPayment(ctx context.Context, r lightRenewalFinalRequest) (lightRenewalResponse, error) {
	snapshot, p, c, err := s.loadBitcoinPayment(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, ok := snapshot.Events["released"]; ok {
		return lightRenewalResponse{State: "released"}, nil
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
	verified, err := verifyBitcoinPaymentFinal(r.Evidence, p, c, registration)
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	digest := hex.EncodeToString(verified.RequestDigest)
	response := lightRenewalResponse{CommitmentTxid: verified.CommitmentTxid, ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout}
	if previous, ok := snapshot.Events["final_authorized"]; ok && previous.RequestDigest != digest {
		return lightRenewalResponse{}, fmt.Errorf("Savings setup final request changed")
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
		return lightRenewalResponse{}, err
	}
	raw, err := json.Marshal(r.Evidence)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if _, _, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "final_authorized", RequestDigest: digest, Evidence: string(raw)}, nil, 0); err != nil {
		return lightRenewalResponse{}, err
	}
	release, err = s.acquireVerification(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	signed, err := s.keys.bitcoinPaymentAuthorization(ctx, bitcoinPaymentAuthorization{context: c, plan: p, registrationPSBT: registration.CanonicalPSBT, registrationMessage: registration.Message, final: &r.Evidence})
	release()
	if err != nil {
		return lightRenewalResponse{}, err
	}
	operator, err := s.dialLightRenewalOperator(ctx)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if err := s.requireFreshBitcoinPayment(ctx, p, c); err != nil {
		return lightRenewalResponse{}, err
	}
	_, created, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "final_dispatched", RequestDigest: digest}, nil, 0)
	if err != nil {
		return lightRenewalResponse{}, err
	}
	if !created {
		response.State = "uncertain"
		return response, nil
	}
	if err := operator.submitLightForfeit(ctx, signed); err != nil {
		response.State = "uncertain"
		return response, nil
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: r.OperationID, Phase: "final_result", RequestDigest: digest, Outcome: "submitted"}); err != nil {
		response.State = "uncertain"
		return response, nil
	}
	response.State = "submitted"
	return response, nil
}
