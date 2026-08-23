package vault

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// PrevFetcher implements arkade.ArkPrevOutFetcher for a single verified
// prevout.
type PrevFetcher struct {
	txscript.PrevOutputFetcher
	op  wire.OutPoint
	tx  *wire.MsgTx
	idx uint32
}

// NewPrevFetcher wraps one outpoint and output.
func NewPrevFetcher(op wire.OutPoint, out *wire.TxOut) *PrevFetcher {
	return &PrevFetcher{
		PrevOutputFetcher: txscript.NewCannedPrevOutputFetcher(out.PkScript, out.Value),
		op:                op,
		idx:               op.Index,
	}
}

// WithPrevTx attaches the verified previous transaction for Arkade signature
// hashing.
func (f *PrevFetcher) WithPrevTx(tx *wire.MsgTx) *PrevFetcher {
	f.tx = tx
	return f
}

func (f *PrevFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if op != f.op {
		return nil
	}
	return f.tx
}

func (f *PrevFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if op != f.op || f.tx == nil || int(f.idx) >= len(f.tx.TxOut) {
		return nil
	}
	return f.tx.TxOut[f.idx].PkScript
}

// RequireVerifiedPrevout loads the Arkade PSBT prevout field and verifies its
// transaction hash, output index, amount, and script against WitnessUtxo.
func RequireVerifiedPrevout(ptx *psbt.Packet) (*wire.MsgTx, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return nil, fmt.Errorf("witness utxo required")
	}
	fields, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevoutTxField)
	if err != nil {
		return nil, err
	}
	if len(fields) != 1 {
		return nil, fmt.Errorf("PrevoutTxField required")
	}
	prev := fields[0]
	op := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	if prev.TxHash() != op.Hash {
		return nil, fmt.Errorf("prevout tx hash mismatch")
	}
	if int(op.Index) >= len(prev.TxOut) {
		return nil, fmt.Errorf("prevout vout out of range")
	}
	want := prev.TxOut[op.Index]
	got := ptx.Inputs[0].WitnessUtxo
	if want == nil || got.Value != want.Value || !bytes.Equal(got.PkScript, want.PkScript) {
		return nil, fmt.Errorf("witness utxo does not match prevout")
	}
	return &prev, nil
}
