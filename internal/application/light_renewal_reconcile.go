package application

import (
	"context"
	"fmt"
	"strconv"
)

type lightRenewalIndexer interface {
	lightRenewalSettled(context.Context, lightRenewalPlan, verifiedLightRenewalFinal, []byte) (bool, error)
}

func (r *arkResolver) lightRenewalSettled(ctx context.Context, p lightRenewalPlan, final verifiedLightRenewalFinal, script []byte) (bool, error) {
	oldKey := p.Txid + ":" + strconv.FormatUint(uint64(p.Vout), 10)
	newKey := final.ReceiverTxid + ":" + strconv.FormatUint(uint64(final.ReceiverVout), 10)
	listed, err := r.listVtxosByOutpoint(ctx, []string{oldKey, newKey})
	if err != nil {
		return false, err
	}
	byID := map[string]indexerVtxo{}
	for _, v := range listed {
		if v.Outpoint.Vout == nil {
			return false, fmt.Errorf("Light renewal indexer outpoint")
		}
		id := v.Outpoint.Txid + ":" + strconv.FormatUint(uint64(*v.Outpoint.Vout), 10)
		if id != oldKey && id != newKey {
			return false, fmt.Errorf("Light renewal indexer unrelated output")
		}
		if _, ok := byID[id]; ok {
			return false, fmt.Errorf("Light renewal indexer duplicate")
		}
		byID[id] = v
	}
	old, ok := byID[oldKey]
	if !ok {
		return false, nil
	}
	if old.IsSpent && old.SettledBy != final.CommitmentTxid {
		return false, fmt.Errorf("Light renewal input settled elsewhere")
	}
	if !old.IsSpent || old.SettledBy != final.CommitmentTxid {
		return false, nil
	}
	prior, err := parseResolvedVtxo(old, script)
	if err != nil || prior.ValueSats != uint64(p.ValueSats) {
		return false, fmt.Errorf("Light renewal old output changed")
	}
	replacement, ok := byID[newKey]
	if !ok {
		return false, nil
	}
	current, err := parseResolvedVtxo(replacement, script)
	if err != nil || current.ValueSats != uint64(p.ReceiverSats) || current.ExpiresAt == nil || prior.ExpiresAt == nil || (!p.bitcoinPayment && *current.ExpiresAt <= *prior.ExpiresAt) {
		return false, fmt.Errorf("Spending replacement value, script, or expiry mismatch")
	}
	matched := false
	for _, commitment := range current.CommitmentTxids {
		if commitment == final.CommitmentTxid {
			matched = true
		}
	}
	if !matched {
		return false, fmt.Errorf("Light renewal replacement commitment changed")
	}
	return true, nil
}

type lightRenewalOperationRequest struct {
	VaultID     string `json:"vaultId"`
	OperationID string `json:"operationId"`
}

func (s *Service) lightRenewalChain() (vaultBoardChain, error) {
	if s.vaultBoardRuntime != nil {
		return s.vaultBoardRuntime.chain, nil
	}
	return dialVaultBoardChain(s.runtimeConfig().Network)
}
