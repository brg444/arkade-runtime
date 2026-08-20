package application

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type execPrevFetcher struct {
	prev map[wire.OutPoint]*wire.TxOut
	vtxo map[wire.OutPoint][]byte
}

func (f execPrevFetcher) FetchPrevOutput(op wire.OutPoint) *wire.TxOut { return f.prev[op] }
func (f execPrevFetcher) FetchPrevOutArkTx(wire.OutPoint) *wire.MsgTx  { return nil }
func (f execPrevFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	return f.vtxo[op]
}

func mustKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func insertEmulatorPacket(t *testing.T, ptx *psbt.Packet, script []byte) {
	t.Helper()
	packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: script})
	if err != nil {
		t.Fatal(err)
	}
	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	if err != nil {
		t.Fatal(err)
	}
	last := len(ptx.UnsignedTx.TxOut) - 1
	if last < 0 || !bytes.Equal(ptx.UnsignedTx.TxOut[last].PkScript, txutils.ANCHOR_PKSCRIPT) {
		t.Fatal("sdk-shaped ark tx must end with p2a")
	}
	anchor := ptx.UnsignedTx.TxOut[last]
	ptx.UnsignedTx.TxOut[last] = txOut
	ptx.UnsignedTx.AddTxOut(anchor)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}

func sdkShapedSpend(t *testing.T, policyScript []byte, dest []byte, inValue, destValue int64, spendLeaf, spendControl []byte) (*psbt.Packet, wire.OutPoint) {
	t.Helper()
	var h chainhash.Hash
	h[0] = 0x42
	op := wire.OutPoint{Hash: h, Index: 0}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(&wire.TxOut{Value: destValue, PkScript: dest})
	tx.AddTxOut(&wire.TxOut{Value: inValue - destValue, PkScript: policyScript})
	tx.AddTxOut(txutils.AnchorOutput())
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	// Checkpoint prevout is not the policy script; FetchVtxoPrevOutPkScript supplies that.
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: inValue, PkScript: append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x11}, 32)...)}
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script:       bytes.Clone(spendLeaf),
		ControlBlock: bytes.Clone(spendControl),
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	return ptx, op
}

func execSpendScript(t *testing.T, ptx *psbt.Packet, policyScript []byte, script []byte, emuBase *btcec.PublicKey, op wire.OutPoint) error {
	t.Helper()
	entry := arkade.EmulatorEntry{Vin: 0, Script: script}
	parsed, err := arkade.ReadArkadeScript(ptx, emuBase, entry)
	if err != nil {
		return err
	}
	fetcher := execPrevFetcher{
		prev: map[wire.OutPoint]*wire.TxOut{op: ptx.Inputs[0].WitnessUtxo},
		vtxo: map[wire.OutPoint][]byte{op: policyScript},
	}
	return parsed.Execute(ptx.UnsignedTx, fetcher, 0)
}

func TestVaultPolicyV1SpendScriptExecutesOnSDKShapedTx(t *testing.T) {
	user, vault, arkd, emu := mustKey(t), mustKey(t), mustKey(t), mustKey(t)
	script, err := policy.VaultPolicyV1SpendArkadeScript()
	if err != nil {
		t.Fatal(err)
	}
	if len(script) == 0 {
		t.Fatal("empty spend script")
	}
	hash := arkade.ArkadeScriptHash(script)
	tweaked := arkade.ComputeArkadeScriptPublicKey(emu.PubKey(), hash)
	del, err := hex.DecodeString(program.VaultPolicyV1PinnedDelegate)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := policy.BuildVaultPolicyV1Tree(policy.VaultPolicyV1Params{
		UserPub:              schnorr.SerializePubKey(user.PubKey()),
		VtxoVaultCosignerPub: schnorr.SerializePubKey(vault.PubKey()),
		TweakedEmulatorPub:   schnorr.SerializePubKey(tweaked),
		ArkdServerPub:        schnorr.SerializePubKey(arkd.PubKey()),
		DelegatePub:          del,
		ExitDevicePub:        schnorr.SerializePubKey(user.PubKey()),
		ExitHardwarePub:      schnorr.SerializePubKey(vault.PubKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	dest := append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x22}, 32)...)
	const inValue, destValue int64 = 20_000, 1_000
	ptx, op := sdkShapedSpend(t, tree.PkScript, dest, inValue, destValue, tree.SpendScript, tree.SpendControlBlock)
	insertEmulatorPacket(t, ptx, script)
	if err := execSpendScript(t, ptx, tree.PkScript, script, emu.PubKey(), op); err != nil {
		t.Fatalf("exact spend script must execute on sdk-shaped one-input flow: %v", err)
	}
	if err := requireExactSpendPacket(ptx, &vtxoPolicyTree{SpendArkadeScript: script}); err != nil {
		t.Fatalf("canonical packet: %v", err)
	}

	t.Run("value leakage", func(t *testing.T) {
		bad, op2 := sdkShapedSpend(t, tree.PkScript, dest, inValue, destValue, tree.SpendScript, tree.SpendControlBlock)
		bad.UnsignedTx.TxOut[0].Value = destValue + 1
		insertEmulatorPacket(t, bad, script)
		if err := execSpendScript(t, bad, tree.PkScript, script, emu.PubKey(), op2); err == nil {
			t.Fatal("dest/change conservation must fail")
		}
	})
	t.Run("wrong change", func(t *testing.T) {
		bad, op2 := sdkShapedSpend(t, tree.PkScript, dest, inValue, destValue, tree.SpendScript, tree.SpendControlBlock)
		bad.UnsignedTx.TxOut[1].PkScript = dest
		insertEmulatorPacket(t, bad, script)
		if err := execSpendScript(t, bad, tree.PkScript, script, emu.PubKey(), op2); err == nil {
			t.Fatal("wrong change script must fail")
		}
	})
	t.Run("non-empty witness", func(t *testing.T) {
		bad, _ := sdkShapedSpend(t, tree.PkScript, dest, inValue, destValue, tree.SpendScript, tree.SpendControlBlock)
		packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: script, Witness: wire.TxWitness{[]byte{0x01}}})
		if err != nil {
			t.Fatal(err)
		}
		ext := extension.Extension{packet}
		txOut, err := ext.TxOut()
		if err != nil {
			t.Fatal(err)
		}
		last := len(bad.UnsignedTx.TxOut) - 1
		anchor := bad.UnsignedTx.TxOut[last]
		bad.UnsignedTx.TxOut[last] = txOut
		bad.UnsignedTx.AddTxOut(anchor)
		if err := requireExactSpendPacket(bad, &vtxoPolicyTree{SpendArkadeScript: script}); err == nil {
			t.Fatal("non-empty packet witness must be rejected")
		}
	})
	t.Run("wrong vin", func(t *testing.T) {
		bad, _ := sdkShapedSpend(t, tree.PkScript, dest, inValue, destValue, tree.SpendScript, tree.SpendControlBlock)
		packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 1, Script: script})
		if err != nil {
			t.Fatal(err)
		}
		ext := extension.Extension{packet}
		txOut, err := ext.TxOut()
		if err != nil {
			t.Fatal(err)
		}
		last := len(bad.UnsignedTx.TxOut) - 1
		anchor := bad.UnsignedTx.TxOut[last]
		bad.UnsignedTx.TxOut[last] = txOut
		bad.UnsignedTx.AddTxOut(anchor)
		if err := requireExactSpendPacket(bad, &vtxoPolicyTree{SpendArkadeScript: script}); err == nil {
			t.Fatal("wrong vin must be rejected")
		}
	})
	t.Run("extra extension packet", func(t *testing.T) {
		bad, _ := sdkShapedSpend(t, tree.PkScript, dest, inValue, destValue, tree.SpendScript, tree.SpendControlBlock)
		insertEmulatorPacket(t, bad, script)
		extra := extension.Extension{extension.UnknownPacket{PacketType: 0x02, Data: []byte{0x01}}}
		txOut, err := extra.TxOut()
		if err != nil {
			t.Fatal(err)
		}
		bad.UnsignedTx.AddTxOut(txOut)
		if err := requireExactSpendPacket(bad, &vtxoPolicyTree{SpendArkadeScript: script}); err == nil {
			t.Fatal("extra extension must be rejected")
		}
	})
}

func TestRequireVerifiedUserSignatureRejectsMissingAndInvalid(t *testing.T) {
	priv := mustKey(t)
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
	ptx.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig, sig}
	if err := requireVerifiedUserSignature(ptx, 0, user, leaf); err == nil {
		t.Fatal("duplicate user signature must be rejected")
	}
}
