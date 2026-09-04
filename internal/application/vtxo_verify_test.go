package application

import (
	"bytes"
	"encoding/hex"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
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

func TestMatchReservedOutpointUsesCanonicalDisplayTxid(t *testing.T) {
	display := make([]byte, chainhash.HashSize)
	for i := range display {
		display[i] = byte(i)
	}
	hash, err := chainhash.NewHashFromStr(hex.EncodeToString(display))
	if err != nil {
		t.Fatal(err)
	}
	const vout = uint32(7)
	want := policy.VtxoOperationInput{Txid: bytes.Clone(display), Vout: int(vout)}
	seen := map[string]policy.VtxoOperationInput{outpointKey(want.Txid, vout): want}
	if got, ok := matchReservedOutpoint(seen, wire.OutPoint{Hash: *hash, Index: vout}); !ok || !bytes.Equal(got.Txid, want.Txid) {
		t.Fatalf("canonical display-order outpoint did not match: %+v, %v", got, ok)
	}

	// A different transaction whose internal chainhash bytes happen to equal
	// the stored display bytes must not match the reservation.
	var byteReversed chainhash.Hash
	copy(byteReversed[:], display)
	if _, ok := matchReservedOutpoint(seen, wire.OutPoint{Hash: byteReversed, Index: vout}); ok {
		t.Fatal("internal-byte-order alias matched a different displayed txid")
	}
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

	displayTxid, err := hex.DecodeString(original.Hash.String())
	if err != nil {
		t.Fatal(err)
	}
	return sdkSpendFixture{
		user: user,
		arkd: arkd,
		tree: tree,
		operation: policy.VtxoOperation{
			AmountSats: 10_000, FeeSats: 0, DestScript: destScript,
			ChangeScript: tree.PkScript, ChangeSats: 10_000, ChangeVout: func() *uint32 { v := uint32(1); return &v }(),
			FeePolicyDigest: bytes.Repeat([]byte{0x44}, 32), CheckpointTapscript: unroll,
		},
		input: policy.VtxoOperationInput{
			Txid: displayTxid, Vout: int(original.Index),
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

func TestVerifyMultiInputSpendRequiresCanonicalCheckpointAlignment(t *testing.T) {
	f := newSDKSpendFixture(t)
	secondCheckpoint, err := clonePacket(f.checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	secondCheckpoint.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0]++
	secondCheckpoint.Inputs[0].TaprootScriptSpendSig = nil
	secondInput := f.input
	secondInput.Txid, err = hex.DecodeString(secondCheckpoint.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String())
	if err != nil {
		t.Fatal(err)
	}

	checkpointScript, arkControl, err := checkpointDestScript(f.operation.CheckpointTapscript, f.tree.SpendLeaf)
	if err != nil {
		t.Fatal(err)
	}
	tx := wire.NewMsgTx(3)
	for _, checkpoint := range []*psbt.Packet{f.checkpoint, secondCheckpoint} {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: checkpoint.UnsignedTx.TxHash(), Index: 0},
			Sequence:         wire.MaxTxInSequenceNum,
		})
	}
	tx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: f.operation.DestScript})
	tx.AddTxOut(&wire.TxOut{Value: 30_000, PkScript: f.tree.PkScript})
	tx.AddTxOut(txutils.AnchorOutput())
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range packet.Inputs {
		packet.Inputs[i].WitnessUtxo = &wire.TxOut{Value: 20_000, PkScript: checkpointScript}
		packet.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			Script: f.tree.SpendLeaf, ControlBlock: arkControl, LeafVersion: txscript.BaseLeafVersion,
		}}
	}
	for i := range packet.Inputs {
		sig, err := signTapLeafAt(packet, i, f.user, f.tree.SpendLeaf)
		if err != nil {
			t.Fatal(err)
		}
		packet.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	}
	f.operation.ChangeSats = 30_000
	inputs := []policy.VtxoOperationInput{f.input, secondInput}
	checkpoints := []*psbt.Packet{f.checkpoint, secondCheckpoint}
	if err := verifySpendPSBT(packet, f.operation, inputs, f.tree, checkpoints); err != nil {
		t.Fatalf("multi-input spend: %v", err)
	}
	if err := verifySpendPSBT(packet, f.operation, inputs, f.tree, []*psbt.Packet{secondCheckpoint, f.checkpoint}); err == nil || !bytes.Contains([]byte(err.Error()), []byte("checkpoint")) {
		t.Fatalf("swapped checkpoints = %v", err)
	}
	if err := verifySpendPSBT(packet, f.operation, inputs, f.tree, checkpoints[:1]); err == nil {
		t.Fatal("checkpoint count mismatch accepted")
	}
}

func TestVerifySpendAllowsNoChangeAndNonzeroFee(t *testing.T) {
	t.Run("no change", func(t *testing.T) {
		f := newSDKSpendFixture(t)
		f.operation.FeeSats = 10_000
		f.operation.ChangeScript = nil
		f.operation.ChangeSats = 0
		f.operation.ChangeVout = nil
		f.arkTx.UnsignedTx.TxOut = []*wire.TxOut{
			f.arkTx.UnsignedTx.TxOut[0],
			f.arkTx.UnsignedTx.TxOut[2],
		}
		f.arkTx.Inputs[0].TaprootScriptSpendSig = nil
		sig, err := signTapLeafAt(f.arkTx, 0, f.user, f.tree.SpendLeaf)
		if err != nil {
			t.Fatal(err)
		}
		f.arkTx.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
		if err := verifySpendPSBT(f.arkTx, f.operation, []policy.VtxoOperationInput{f.input}, f.tree, []*psbt.Packet{f.checkpoint}); err != nil {
			t.Fatalf("no-change spend: %v", err)
		}
	})

	t.Run("change", func(t *testing.T) {
		f := newSDKSpendFixture(t)
		f.operation.FeeSats = 500
		f.operation.ChangeSats = 9_500
		f.arkTx.UnsignedTx.TxOut[1].Value = 9_500
		f.arkTx.Inputs[0].TaprootScriptSpendSig = nil
		sig, err := signTapLeafAt(f.arkTx, 0, f.user, f.tree.SpendLeaf)
		if err != nil {
			t.Fatal(err)
		}
		f.arkTx.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
		if err := verifySpendPSBT(f.arkTx, f.operation, []policy.VtxoOperationInput{f.input}, f.tree, []*psbt.Packet{f.checkpoint}); err != nil {
			t.Fatalf("fee spend: %v", err)
		}
	})
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
	if err := enforceVtxoAmount(^uint64(0), 0, nil); err == nil {
		t.Fatal("uint64 amount wraparound must be rejected")
	}
	if err := enforceVtxoAmount(10_000, ^uint64(0), nil); err == nil {
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
