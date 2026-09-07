package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
)

func (s *Service) reconcileSpendingDelegation(ctx context.Context, saved *policy.LightDelegationSnapshot, p lightDelegationPlan, c renewalContract) (bool, error) {
	tree := c.Tree

	if _, ok := saved.Events["confirmed"]; ok {
		return true, nil
	}
	event, ok := saved.Events["final_authorized"]
	if !ok {
		return false, nil
	}
	var final lightDelegationFinal
	if err := json.Unmarshal([]byte(event.Evidence), &final); err != nil {
		return false, err
	}
	_, registration, err := validateRenewalDelegationCapability(c, p)
	if err != nil {
		return false, err
	}
	verified, err := verifyRenewalFinal(final.Evidence, p.Renewal, c, registration, delegatedOwnerSighash)
	if err != nil {
		return false, err
	}
	indexer, ok := s.ArkResolver.(lightRenewalIndexer)
	if !ok {
		return false, fmt.Errorf("Light delegation settlement reconciliation unavailable")
	}
	settled, err := indexer.lightRenewalSettled(ctx, p.Renewal, verified, tree.PkScript)
	if err != nil || !settled {
		return false, err
	}
	chain, err := s.lightRenewalChain()
	if err != nil {
		return false, err
	}
	confirmed, err := chain.confirmedOutpoint(ctx, verified.CommitmentTxid, 0)
	if err != nil {
		return false, err
	}
	packet, err := parsePSBT(final.Evidence.CommitmentPSBT)
	if err != nil {
		return false, err
	}
	if confirmed.ValueSats != packet.UnsignedTx.TxOut[0].Value || !bytes.Equal(confirmed.PkScript, packet.UnsignedTx.TxOut[0].PkScript) {
		return false, fmt.Errorf("Light delegation Bitcoin commitment mismatch")
	}
	coins, err := s.ArkResolver.SpendableVtxos(ctx, tree.PkScript)
	if err != nil {
		return false, err
	}
	expires := int64(0)
	for _, coin := range coins {
		if coin.Txid == verified.ReceiverTxid && coin.Vout == verified.ReceiverVout && coin.ValueSats == uint64(p.Renewal.ReceiverSats) && coin.ExpiresAt != nil {
			expires = *coin.ExpiresAt
		}
	}
	// A subsequently spent replacement is still a successful renewal. The
	// independent settled() check above already verifies both exact outputs;
	// expiry may be unavailable to the spendable-only listing in that case.
	_, err = s.persistDelegation(p.Request.OperationID, "confirmed", struct {
		CommitmentTxid    string `json:"commitmentTxid"`
		ReceiverTxid      string `json:"receiverTxid"`
		ReceiverVout      uint32 `json:"receiverVout"`
		ReceiverExpiresAt int64  `json:"receiverExpiresAt"`
		BlockHash         string `json:"blockHash"`
		BlockHeight       int64  `json:"blockHeight"`
	}{verified.CommitmentTxid, verified.ReceiverTxid, verified.ReceiverVout, expires, confirmed.FundingBlockHash, confirmed.FundingBlockHeight})
	return err == nil, err
}
