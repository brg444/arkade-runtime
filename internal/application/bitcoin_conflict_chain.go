package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/wire"
)

type bitcoinConflictChain interface {
	confirmedBitcoinConflict(context.Context, string, *wire.MsgTx) (*policy.BitcoinConflictEvidence, error)
}

// The pinned Esplora service is the existing chain authority. Raw transaction
// bytes independently bind its reported spender to a real commitment input.
func (e *esploraVaultBoardChain) confirmedBitcoinConflict(ctx context.Context, network string, commitment *wire.MsgTx) (*policy.BitcoinConflictEvidence, error) {
	if commitment == nil || len(commitment.TxIn) == 0 || len(commitment.TxIn) > 128 {
		return nil, fmt.Errorf("bounded Bitcoin commitment inputs required")
	}
	if err := e.verifyCheckpoint(ctx, network); err != nil {
		return nil, err
	}
	for _, input := range commitment.TxIn {
		funding := input.PreviousOutPoint
		spent, err := e.getOutspend(ctx, funding.Hash.String(), funding.Index)
		if err != nil {
			return nil, err
		}
		if !spent.Spent || spent.Txid == commitment.TxHash().String() {
			continue
		}
		if requireTxid(spent.Txid) != nil || spent.Vin < 0 || spent.Vin > (1<<32)-1 {
			return nil, fmt.Errorf("Bitcoin conflict outspend is invalid")
		}
		var status vaultBoardEsploraStatus
		if err := e.getJSON(ctx, "/tx/"+spent.Txid+"/status", vaultBoardChainBlockLimit, &status); err != nil {
			return nil, err
		}
		if !status.Confirmed {
			continue
		}
		if status.BlockHeight <= 0 || requireTxid(status.BlockHash) != nil {
			return nil, fmt.Errorf("Bitcoin conflict confirmation is invalid")
		}
		raw, err := e.getText(ctx, "/tx/"+spent.Txid+"/hex", vaultBoardChainTxLimit)
		if err != nil {
			return nil, err
		}
		proof := policy.BitcoinConflictEvidence{Kind: policy.BitcoinConflictKind,
			CommitmentTxid: commitment.TxHash().String(), FundingTxid: funding.Hash.String(), FundingVout: funding.Index,
			ConflictingTxid: spent.Txid, ConflictingVin: uint32(spent.Vin), BlockHash: status.BlockHash,
			BlockHeight: status.BlockHeight, RawTransaction: raw}
		if err := verifyBitcoinConflictTransaction(proof, commitment); err != nil {
			return nil, err
		}
		tipHash, err := e.getText(ctx, "/blocks/tip/hash", vaultBoardChainTextLimit)
		if err != nil || requireTxid(tipHash) != nil {
			return nil, fmt.Errorf("Bitcoin conflict chain tip unavailable")
		}
		var tip vaultBoardEsploraBlock
		if err := e.getJSON(ctx, "/block/"+tipHash, vaultBoardChainBlockLimit, &tip); err != nil {
			return nil, err
		}
		if err := validateVaultBoardBlock(tip, tipHash, tip.Height); err != nil {
			return nil, err
		}
		if tip.Height < status.BlockHeight || tip.Height-status.BlockHeight < policy.BitcoinConflictConfirmations-1 {
			continue
		}
		proof.TipHash, proof.TipHeight = tipHash, tip.Height
		// Read confirmation and spender again, then bind both heights to the
		// canonical chain. A changing status, outspend, or fork fails closed.
		var again vaultBoardEsploraStatus
		if err := e.getJSON(ctx, "/tx/"+spent.Txid+"/status", vaultBoardChainBlockLimit, &again); err != nil {
			return nil, err
		}
		current, err := e.getOutspend(ctx, funding.Hash.String(), funding.Index)
		if err != nil || current != spent || again != status {
			return nil, fmt.Errorf("Bitcoin conflict changed during query")
		}
		for _, block := range []struct {
			height int64
			hash   string
		}{{tip.Height, tipHash}, {status.BlockHeight, status.BlockHash}} {
			canonical, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(block.height, 10), vaultBoardChainTextLimit)
			if err != nil || canonical != block.hash {
				return nil, fmt.Errorf("Bitcoin conflict block is not canonical")
			}
		}
		if err := proof.Validate(); err != nil {
			return nil, err
		}
		return &proof, nil
	}
	return nil, nil
}

func verifyBitcoinConflictTransaction(p policy.BitcoinConflictEvidence, commitment *wire.MsgTx) error {
	raw, err := hex.DecodeString(p.RawTransaction)
	if err != nil || hex.EncodeToString(raw) != p.RawTransaction || len(raw) > vaultBoardChainTxLimit/2 {
		return fmt.Errorf("Bitcoin conflict transaction encoding")
	}
	r := bytes.NewReader(raw)
	var tx wire.MsgTx
	if err := tx.Deserialize(r); err != nil || r.Len() != 0 || tx.TxHash().String() != p.ConflictingTxid ||
		uint64(p.ConflictingVin) >= uint64(len(tx.TxIn)) || p.ConflictingTxid == commitment.TxHash().String() || p.CommitmentTxid != commitment.TxHash().String() {
		return fmt.Errorf("Bitcoin conflict transaction does not match")
	}
	prev := tx.TxIn[p.ConflictingVin].PreviousOutPoint
	if prev.Hash.String() != p.FundingTxid || prev.Index != p.FundingVout {
		return fmt.Errorf("Bitcoin conflict input changed")
	}
	for _, input := range commitment.TxIn {
		if input.PreviousOutPoint == prev {
			return nil
		}
	}
	return fmt.Errorf("Bitcoin conflict does not spend a commitment input")
}
