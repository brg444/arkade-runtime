package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
)

func (s *Service) releaseConflictedBitcoinPayment(ctx context.Context, snapshot *policy.LightRenewalSnapshot, p bitcoinPaymentPlan, c bitcoinPaymentContext, evidence lightRenewalFinalEvidence, final verifiedLightRenewalFinal) (bool, error) {
	chain, err := s.lightRenewalChain()
	if err != nil {
		return false, err
	}
	verifier, ok := chain.(bitcoinConflictChain)
	if !ok {
		return false, nil
	}
	packet, err := parseCanonicalVaultBoardPSBT(evidence.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || packet.UnsignedTx.TxHash().String() != final.CommitmentTxid {
		return false, fmt.Errorf("Bitcoin conflict commitment changed")
	}
	proof, err := verifier.confirmedBitcoinConflict(ctx, c.spending.Binding.Network, packet.UnsignedTx)
	if err != nil || proof == nil {
		return false, err
	}
	if err := proof.Validate(); err != nil {
		return false, err
	}
	if err := verifyBitcoinConflictTransaction(*proof, packet.UnsignedTx); err != nil {
		return false, err
	}
	// Keep the original reservation if the input has already moved, disappeared,
	// or changed. No new signing is performed during reconciliation.
	input, err := s.liveRenewalInput(ctx, c.spending.Tree, p.Txid, p.Vout)
	if err != nil || input.ValueSats != uint64(p.ValueSats) {
		return false, nil
	}
	digest := hex.EncodeToString(final.RequestDigest)
	if digest != snapshot.Events["final_dispatched"].RequestDigest {
		return false, fmt.Errorf("Bitcoin conflict dispatch changed")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return false, err
	}
	// The ledger's existing mutex/sequence transaction makes release atomic
	// against confirmation or any late final-result callback, retaining all
	// original signed evidence and the new canonical-chain evidence.
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: p.OperationID, Phase: "released", RequestDigest: digest, Evidence: string(raw)}); err != nil {
		return false, err
	}
	return true, nil
}
