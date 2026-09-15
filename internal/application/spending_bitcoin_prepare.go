package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
)

type bitcoinPaymentPrepared struct {
	Plan       bitcoinPaymentPlan `json:"plan"`
	PlanDigest string             `json:"planDigest"`
	State      string             `json:"state"`
}

func (s *Service) bitcoinPaymentContext(vault string) (bitcoinPaymentContext, error) {
	spending, err := s.spendingRenewalContext(vault)
	if err != nil {
		return bitcoinPaymentContext{}, err
	}
	return bitcoinPaymentContext{spending: renewalContract{spendingRenewalContext: spending}}, nil
}

func (s *Service) bitcoinPaymentFee(ctx context.Context, v ports.ResolvedVtxo, p bitcoinPaymentPlan, c bitcoinPaymentContext) (uint64, string, error) {
	fees, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return 0, "", err
	}
	estimator, digest, err := newVtxoFeeEstimator(fees)
	if err != nil {
		return 0, "", err
	}
	outputs := []arkfee.Output{}
	for _, output := range p.Outputs {
		outputs = append(outputs, arkfee.Output{Amount: uint64(output.AmountSats), Script: output.Script})
	}
	release, err := s.acquireFeeSelection(ctx)
	if err != nil {
		return 0, "", err
	}
	defer release()
	amount, err := estimator.Eval([]arkfee.OffchainInput{resolvedArkFeeInput(v)}, nil, []arkfee.Output{{Amount: uint64(p.ChangeSats), Script: c.spending.Binding.ScriptPubKey}}, outputs)
	if err != nil {
		return 0, "", err
	}
	fee, err := exactFeeSats(amount)
	return fee, hex.EncodeToString(digest), err
}

func (s *Service) reserveBitcoinPlan(ctx context.Context, v ports.ResolvedVtxo, p bitcoinPaymentPlan, c bitcoinPaymentContext) (bitcoinPaymentPrepared, error) {
	p.ChangeSats = p.ValueSats - p.principal()
	stable := false
	for i := 0; i < 8; i++ {
		if p.ChangeSats < 330 {
			return bitcoinPaymentPrepared{}, apperr.New(apperr.CodeRejected, "the payment leaves less protected change than the network dust minimum; try a smaller amount")
		}
		fee, feeDigest, err := s.bitcoinPaymentFee(ctx, v, p, c)
		if err != nil {
			return bitcoinPaymentPrepared{}, err
		}
		if fee > 5000 || fee > uint64(c.spending.Binding.SpendingPolicy.AbsoluteFeeCapSats) {
			return bitcoinPaymentPrepared{}, apperr.New(apperr.CodeRejected, "the network fee exceeds this device's limit; try a smaller amount or retry later")
		}
		p.FeeSats, p.FeePolicyDigest = int64(fee), feeDigest
		next := p.ValueSats - p.principal() - p.FeeSats
		if next == p.ChangeSats {
			stable = true
			break
		}
		p.ChangeSats = next
	}
	if !stable {
		return bitcoinPaymentPrepared{}, apperr.New(apperr.CodeRejected, "the network fee could not be finalized; retry the payment")
	}
	digest, err := p.digest(c)
	if err != nil {
		return bitcoinPaymentPrepared{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return bitcoinPaymentPrepared{}, err
	}
	op := policy.SpendingRenewalOperation{OperationID: p.OperationID, VaultID: p.VaultID, InputTxid: p.Txid, InputVout: p.Vout, FeeSats: p.FeeSats, PlanDigest: hex.EncodeToString(digest), Plan: string(raw), ExpiresAt: time.Unix(p.RegisterExpireAt, 0).UTC().Format(time.RFC3339), Kind: policy.SpendingBitcoinBatchKind, AmountSats: p.principal()}
	saved, err := s.Stores.SpendingRenewal.ReserveSpendingRenewal(ctx, op, c.spending.Binding.SpendingPolicy.PeriodAllowanceSats)
	if err != nil {
		return bitcoinPaymentPrepared{}, mapLedgerBusy(err)
	}
	return bitcoinPaymentSnapshot(saved, c)
}

func bitcoinPaymentSnapshot(s *policy.SpendingRenewalSnapshot, c bitcoinPaymentContext) (bitcoinPaymentPrepared, error) {
	var p bitcoinPaymentPlan
	if s == nil || s.Operation.Kind != policy.SpendingBitcoinBatchKind || json.Unmarshal([]byte(s.Operation.Plan), &p) != nil {
		return bitcoinPaymentPrepared{}, fmt.Errorf("Bitcoin payment operation required")
	}
	digest, err := p.digest(c)
	if err != nil || hex.EncodeToString(digest) != s.Operation.PlanDigest || p.OperationID != s.Operation.OperationID || p.VaultID != s.Operation.VaultID || p.Txid != s.Operation.InputTxid || p.Vout != s.Operation.InputVout || p.FeeSats != s.Operation.FeeSats || p.principal() != s.Operation.AmountSats || time.Unix(p.RegisterExpireAt, 0).UTC().Format(time.RFC3339) != s.Operation.ExpiresAt {
		return bitcoinPaymentPrepared{}, fmt.Errorf("Bitcoin payment stored plan mismatch")
	}
	return bitcoinPaymentPrepared{p, s.Operation.PlanDigest, spendingRenewalState(s)}, nil
}

func (s *Service) requireFreshBitcoinPayment(ctx context.Context, p bitcoinPaymentPlan, c bitcoinPaymentContext) error {
	if p.RegisterExpireAt-s.vtxoNow().Unix() < 15 {
		return fmt.Errorf("Bitcoin payment authorization expired")
	}
	v, err := s.liveRenewalInput(ctx, c.spending.Tree, p.Txid, p.Vout)
	if err != nil || int64(v.ValueSats) != p.ValueSats {
		return fmt.Errorf("Bitcoin payment input unavailable")
	}
	fee, digest, err := s.bitcoinPaymentFee(ctx, v, p, c)
	if err != nil || int64(fee) != p.FeeSats || digest != p.FeePolicyDigest {
		return fmt.Errorf("Bitcoin payment fee changed")
	}
	return nil
}
