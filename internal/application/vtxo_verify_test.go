package application

import (
	"bytes"
	"encoding/hex"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type sdkSpendFixture struct {
	user       *btcec.PrivateKey
	arkd       *btcec.PrivateKey
	tree       *vtxoPolicyTree
	operation  policy.VtxoOperation
	input      policy.VtxoOperationInput
	checkpoint *psbt.Packet
	arkTx      *psbt.Packet
}

func newSDKSpendFixture(t *testing.T) sdkSpendFixture {
	t.Helper()
	user := mustVtxoTestKey(t)
	vault := mustVtxoTestKey(t)
	arkd := mustVtxoTestKey(t)
	hardware := mustVtxoTestKey(t)
	delegate, err := hex.DecodeString(program.VaultPolicyV1PinnedDelegate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := policy.BuildVaultPolicyV1Tree(policy.VaultPolicyV1Params{
		UserPub:              schnorr.SerializePubKey(user.PubKey()),
		VtxoVaultCosignerPub: schnorr.SerializePubKey(vault.PubKey()),
		ArkdServerPub:        schnorr.SerializePubKey(arkd.PubKey()),
		DelegatePub:          delegate,
		ExitDevicePub:        schnorr.SerializePubKey(user.PubKey()),
		ExitHardwarePub:      schnorr.SerializePubKey(hardware.PubKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	tree := &vtxoPolicyTree{
		CosignerPub:     vault.PubKey(),
		ArkdPub:         arkd.PubKey(),
		PkScript:        encoded.PkScript,
		SpendLeaf:       encoded.SpendScript,
		SpendControl:    encoded.SpendControlBlock,
		DelegateLeaf:    encoded.DelegateScript,
		DelegateControl: encoded.DelegateControlBlock,
	}
	unrollClosure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{arkd.PubKey()}}
	unroll, err := unrollClosure.Script()
	if err != nil {
		t.Fatal(err)
	}
	checkpointScript, checkpointControl, err := checkpointDestScript(unroll, tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}

	var originalHash chainhash.Hash
	originalHash[0] = 0x42
	original := wire.OutPoint{Hash: originalHash, Index: 7}
	const inputValue int64 = 20_000
	cpTx := wire.NewMsgTx(3)
	cpTx.AddTxIn(&wire.TxIn{PreviousOutPoint: original, Sequence: wire.MaxTxInSequenceNum})
	cpTx.AddTxOut(&wire.TxOut{Value: inputValue, PkScript: checkpointScript})
	cpTx.AddTxOut(txutils.AnchorOutput())
	cp, err := psbt.NewFromUnsignedTx(cpTx)
	if err != nil {
		t.Fatal(err)
	}
	cp.Inputs[0].WitnessUtxo = &wire.TxOut{Value: inputValue, PkScript: tree.PkScript}
	cp.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: tree.SpendLeaf, ControlBlock: tree.SpendControl, LeafVersion: txscript.BaseLeafVersion,
	}}
	userCheckpointSig, err := signTapLeafAt(cp, 0, user, tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	cp.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{userCheckpointSig}

	destScript := append([]byte{txscript.OP_1, txscript.OP_DATA_32}, bytes.Repeat([]byte{0x33}, 32)...)
	arkTx := wire.NewMsgTx(3)
	arkTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: cpTx.TxHash(), Index: 0},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	arkTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: destScript})
	arkTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: tree.PkScript})
	arkTx.AddTxOut(txutils.AnchorOutput())
	arkPacket, err := psbt.NewFromUnsignedTx(arkTx)
	if err != nil {
		t.Fatal(err)
	}
	arkPacket.Inputs[0].WitnessUtxo = &wire.TxOut{Value: inputValue, PkScript: checkpointScript}
	arkPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: tree.SpendLeaf, ControlBlock: checkpointControl, LeafVersion: txscript.BaseLeafVersion,
	}}
	userArkSig, err := signTapLeafAt(arkPacket, 0, user, tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	arkPacket.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{userArkSig}

	return sdkSpendFixture{
		user: user,
		arkd: arkd,
		tree: tree,
		operation: policy.VtxoOperation{
			AmountSats: 10_000, FeeSats: 0, DestScript: destScript,
			ChangeScript: tree.PkScript, CheckpointTapscript: unroll,
		},
		input: policy.VtxoOperationInput{
			Txid: bytes.Clone(original.Hash[:]), Vout: int(original.Index),
			ValueSats: inputValue, Script: tree.PkScript,
		},
		checkpoint: cp,
		arkTx:      arkPacket,
	}
}

func TestVerifySDKNativeSpendShape(t *testing.T) {
	f := newSDKSpendFixture(t)
	unsigned, err := clonePacket(f.checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Inputs[0].TaprootScriptSpendSig = nil
	if err := verifyUnsignedCheckpointPSBT(unsigned, f.input, f.operation, f.tree); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := verifySpendPSBT(f.arkTx, f.operation, []policy.VtxoOperationInput{f.input}, f.tree, []*psbt.Packet{f.checkpoint}); err != nil {
		t.Fatalf("ark tx: %v", err)
	}
	if len(f.checkpoint.UnsignedTx.TxOut) != 2 || len(f.arkTx.UnsignedTx.TxOut) != 3 {
		t.Fatal("SDK-native output shape changed")
	}
}

func TestVerifySubmittedCheckpointRequiresExactUserAndOperatorStage(t *testing.T) {
	f := newSDKSpendFixture(t)
	operatorSig, err := signTapLeafAt(f.checkpoint, 0, f.arkd, f.tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	f.checkpoint.Inputs[0].TaprootScriptSpendSig = append(f.checkpoint.Inputs[0].TaprootScriptSpendSig, operatorSig)
	if err := verifySubmittedCheckpointPSBT(f.checkpoint, f.input, f.operation, f.tree); err != nil {
		t.Fatalf("submitted checkpoint: %v", err)
	}

	missing, err := clonePacket(f.checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	missing.Inputs[0].TaprootScriptSpendSig = missing.Inputs[0].TaprootScriptSpendSig[:1]
	if err := verifySubmittedCheckpointPSBT(missing, f.input, f.operation, f.tree); err == nil {
		t.Fatal("checkpoint without Operator signature accepted")
	}

	if err := verifyUnsignedCheckpointPSBT(f.checkpoint, f.input, f.operation, f.tree); err == nil {
		t.Fatal("pre-signed checkpoint accepted before submit")
	}
}

func TestVerifySDKNativeSpendRejectsExtensionAndValueLeak(t *testing.T) {
	f := newSDKSpendFixture(t)

	extra, err := clonePacket(f.arkTx)
	if err != nil {
		t.Fatal(err)
	}
	anchor := extra.UnsignedTx.TxOut[2]
	extra.UnsignedTx.TxOut[2] = &wire.TxOut{Value: 0, PkScript: []byte{txscript.OP_RETURN, 0x01, 0x01}}
	extra.UnsignedTx.AddTxOut(anchor)
	extra.Outputs = append(extra.Outputs, psbt.POutput{})
	if err := verifySpendPSBT(extra, f.operation, []policy.VtxoOperationInput{f.input}, f.tree, []*psbt.Packet{f.checkpoint}); err == nil {
		t.Fatal("extension output must be rejected")
	}

	leak, err := clonePacket(f.arkTx)
	if err != nil {
		t.Fatal(err)
	}
	leak.UnsignedTx.TxOut[1].Value--
	if err := verifySpendPSBT(leak, f.operation, []policy.VtxoOperationInput{f.input}, f.tree, []*psbt.Packet{f.checkpoint}); err == nil {
		t.Fatal("value leakage must be rejected")
	}
}

func TestUnsignedPSBTEqualIncludesSignatureBytesAndSighashType(t *testing.T) {
	f := newSDKSpendFixture(t)
	other, err := clonePacket(f.arkTx)
	if err != nil {
		t.Fatal(err)
	}
	if !unsignedPSBTEqual(f.arkTx, other) {
		t.Fatal("identical packets differ")
	}
	other.Inputs[0].TaprootScriptSpendSig[0].Signature[0] ^= 1
	if unsignedPSBTEqual(f.arkTx, other) {
		t.Fatal("changed signature bytes accepted as replay")
	}
	other, err = clonePacket(f.arkTx)
	if err != nil {
		t.Fatal(err)
	}
	other.Inputs[0].SighashType = txscript.SigHashAll
	if unsignedPSBTEqual(f.arkTx, other) {
		t.Fatal("changed PSBT sighash accepted as replay")
	}
}

func TestEnforceVtxoAmountRejectsUint64Wraparound(t *testing.T) {
	if err := enforceVtxoAmount(^uint64(0), 0, nil, enrolledSnapshot{}); err == nil {
		t.Fatal("uint64 amount wraparound must be rejected")
	}
	if err := enforceVtxoAmount(10_000, ^uint64(0), nil, enrolledSnapshot{}); err == nil {
		t.Fatal("uint64 fee wraparound must be rejected")
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
