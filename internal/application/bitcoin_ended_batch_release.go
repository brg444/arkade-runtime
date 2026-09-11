package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
)

type endedCommitmentOperator interface {
	endedCommitmentAt(context.Context, string) (int64, error)
}

// releaseEndedBitcoinPayment handles a final request whose durable dispatch
// fence was crossed only after the exact Operator batch had already ended.
// The ended batch is irreversible, and the original VTXO must independently
// remain live before the ledger releases its reservation.
func (s *Service) releaseEndedBitcoinPayment(ctx context.Context, snapshot *policy.LightRenewalSnapshot, p bitcoinPaymentPlan, c bitcoinPaymentContext, final verifiedLightRenewalFinal) (bool, error) {
	if snapshot.Events["final_result"].Phase != "" {
		return false, nil
	}
	dispatch := snapshot.Events["final_dispatched"]
	dispatchedAt, err := time.Parse(time.RFC3339, dispatch.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("Bitcoin payment dispatch time changed")
	}
	operator, err := s.dialLightRenewalOperator(ctx)
	if err != nil {
		return false, err
	}
	status, ok := operator.(endedCommitmentOperator)
	if !ok {
		return false, nil
	}
	endedAt, err := status.endedCommitmentAt(ctx, final.CommitmentTxid)
	if err != nil {
		return false, err
	}
	// Equal second-resolution timestamps cannot establish request ordering.
	if endedAt <= 0 || dispatchedAt.Unix() <= endedAt {
		return false, nil
	}
	input, err := s.liveRenewalInput(ctx, c.spending.Tree, p.Txid, p.Vout)
	if err != nil || input.ValueSats != uint64(p.ValueSats) || input.ExpiresAt == nil {
		return false, nil
	}
	proof := policy.BitcoinEndedBatchEvidence{
		Kind:                 policy.BitcoinEndedBatchKind,
		CommitmentTxid:       final.CommitmentTxid,
		BatchEndedAt:         endedAt,
		FinalDispatchedAt:    dispatch.CreatedAt,
		InputTxid:            input.Txid,
		InputVout:            input.Vout,
		InputValueSats:       input.ValueSats,
		InputExpiresAt:       *input.ExpiresAt,
		InputCommitmentTxids: append([]string(nil), input.CommitmentTxids...),
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return false, err
	}
	digest := hex.EncodeToString(final.RequestDigest)
	if digest != dispatch.RequestDigest {
		return false, fmt.Errorf("Bitcoin ended-batch dispatch changed")
	}
	if err := s.persistLightRenewalEvent(policy.LightRenewalEvent{OperationID: p.OperationID, Phase: "released", RequestDigest: digest, Evidence: string(raw)}); err != nil {
		return false, err
	}
	return true, nil
}
