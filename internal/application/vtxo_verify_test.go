package application

import (
	"bytes"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func TestVerifySpendRejectsFeeBurnAndWrongShape(t *testing.T) {
	tree := &vtxoPolicyTree{PkScript: bytes.Repeat([]byte{0x51}, 34), SpendArkadeScript: []byte{0x51}}
	op := policy.VtxoOperation{AmountSats: 10_000, FeeSats: 0, DestScript: bytes.Repeat([]byte{0x00}, 22), ChangeScript: tree.PkScript}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: op.DestScript})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: tree.PkScript}) // below dust
	tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: []byte{0x6a}})
	tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: txutils.ANCHOR_PKSCRIPT})
	pkt, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 10_001, PkScript: bytes.Repeat([]byte{0x51}, 34)}
	if err := verifySpendPSBT(pkt, op, []policy.VtxoOperationInput{{ValueSats: 10_001}}, tree, []*psbt.Packet{pkt}); err == nil {
		t.Fatal("below-dust change / missing packet must be rejected")
	}
}

func TestVerifySpendRejectsUnexpectedOutput(t *testing.T) {
	tree := &vtxoPolicyTree{PkScript: bytes.Repeat([]byte{0x51}, 34)}
	op := policy.VtxoOperation{AmountSats: 10_000, DestScript: bytes.Repeat([]byte{0x00}, 22), ChangeScript: tree.PkScript}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: op.DestScript})
	pkt, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySpendPSBT(pkt, op, []policy.VtxoOperationInput{{}}, tree, []*psbt.Packet{pkt}); err == nil {
		t.Fatal("wrong output count must be rejected")
	}
}

func TestControlBlockRejectsWrongPrevout(t *testing.T) {
	if err := controlBlockMatches([]byte{0x51}, []byte{0x51}, []byte{0xc0}); err == nil {
		t.Fatal("garbage control block must be rejected")
	}
}

func TestProgramPins(t *testing.T) {
	if program.VaultPolicyV1ExitDelay != 4608 {
		t.Fatal(program.VaultPolicyV1ExitDelay)
	}
}
