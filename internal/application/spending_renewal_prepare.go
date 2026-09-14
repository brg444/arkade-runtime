package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
)

func (s *Service) liveRenewalInput(ctx context.Context, tree *vtxoPolicyTree, txid string, vout uint32) (ports.ResolvedVtxo, error) {

	all, err := s.ArkResolver.SpendableVtxos(ctx, tree.PkScript)
	if err != nil {
		return ports.ResolvedVtxo{}, err
	}
	var found *ports.ResolvedVtxo
	for _, v := range all {
		if v.Txid != txid || v.Vout != vout {
			continue
		}
		if found != nil || !bytes.Equal(v.Script, tree.PkScript) || v.ValueSats < 330 || v.ValueSats > 21_000_000*100_000_000 || v.IsSwept || v.ExpiresAt == nil || *v.ExpiresAt <= s.vtxoNow().Unix() || len(v.CommitmentTxids) == 0 {
			return ports.ResolvedVtxo{}, fmt.Errorf("Light renewal requires one live committed output")
		}
		copy := v
		found = &copy
	}
	if found == nil {
		return ports.ResolvedVtxo{}, fmt.Errorf("Light renewal input unavailable")
	}
	return *found, nil
}
func (s *Service) spendingRenewalFee(ctx context.Context, v ports.ResolvedVtxo, script []byte, receiver uint64) (uint64, string, error) {
	policy, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return 0, "", err
	}
	estimator, digest, err := newVtxoFeeEstimator(policy)
	if err != nil {
		return 0, "", err
	}
	release, err := s.acquireFeeSelection(ctx)
	if err != nil {
		return 0, "", err
	}
	defer release()
	amount, err := estimator.Eval([]arkfee.OffchainInput{resolvedArkFeeInput(v)}, nil, []arkfee.Output{{Amount: receiver, Script: hex.EncodeToString(script)}}, nil)
	if err != nil {
		return 0, "", err
	}
	fee, err := exactFeeSats(amount)
	return fee, hex.EncodeToString(digest), err
}

func spendingRenewalState(s *policy.SpendingRenewalSnapshot) string {
	for _, phase := range []string{"confirmed", "released", "cancelled", "final_result", "final_dispatched", "final_authorized", "delete_result", "delete_dispatched", "delete_authorized", "register_result", "register_dispatched", "register_authorized"} {
		if e, ok := s.Events[phase]; ok {
			if e.Outcome != "" {
				return e.Outcome
			}
			return phase
		}
	}
	return "prepared"
}
