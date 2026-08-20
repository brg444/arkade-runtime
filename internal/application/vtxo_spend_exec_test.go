package application

import (
	"bytes"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func mustVtxoTestKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRequireVerifiedUserSignatureRejectsMissingWrongSighashAndDuplicate(t *testing.T) {
	priv := mustVtxoTestKey(t)
	closure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{priv.PubKey()}}
	leaf, err := closure.Script()
	if err != nil {
		t.Fatal(err)
	}
	tx := wire.NewMsgTx(3)
	var h chainhash.Hash
	h[0] = 1
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: h}, Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: bytes.Repeat([]byte{0x51}, 34)})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2000, PkScript: bytes.Repeat([]byte{0x51}, 34)}
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: leaf, ControlBlock: bytes.Repeat([]byte{0xc0}, 33), LeafVersion: txscript.BaseLeafVersion,
	}}
	user := schnorr.SerializePubKey(priv.PubKey())
	if err := requireVerifiedUserSignature(ptx, 0, user, leaf); err == nil {
		t.Fatal("missing user signature must be rejected")
	}
	sig, err := signTapLeafAt(ptx, 0, priv, leaf)
	if err != nil {
		t.Fatal(err)
	}
	ptx.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	if err := requireVerifiedUserSignature(ptx, 0, user, leaf); err != nil {
		t.Fatal(err)
	}
	if err := requireVerifiedUserSignatureWithSighash(ptx, 0, user, leaf, txscript.SigHashAll); err == nil {
		t.Fatal("wrong sighash must be rejected")
	}
	ptx.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig, sig}
	if err := requireVerifiedUserSignature(ptx, 0, user, leaf); err == nil {
		t.Fatal("duplicate user signature must be rejected")
	}
}

func TestVtxoPostSubmitStateMachine(t *testing.T) {
	if !vtxoCheckpointAuthorizableState("signed") || !vtxoCheckpointAuthorizableState("submitted") {
		t.Fatal("checkpoint authorization must accept the first request and its replay")
	}
	if vtxoCheckpointAuthorizableState("reserved") || vtxoCheckpointAuthorizableState("finalized") {
		t.Fatal("checkpoint authorization accepted an invalid state")
	}
	if !vtxoFinalizableState("submitted") {
		t.Fatal("Operator finalization must follow checkpoint authorization")
	}
	if vtxoFinalizableState("signed") || vtxoFinalizableState("reserved") {
		t.Fatal("finalization accepted a pre-checkpoint state")
	}
}
