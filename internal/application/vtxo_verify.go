package application

import (
	"bytes"
	"fmt"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func controlBlockMatches(pkScript, leafScript, control []byte) error {
	if len(pkScript) == 0 || len(leafScript) == 0 || len(control) == 0 {
		return fmt.Errorf("control block")
	}
	cb, err := txscript.ParseControlBlock(control)
	if err != nil {
		return fmt.Errorf("control block: %w", err)
	}
	root := cb.RootHash(leafScript)
	tapKey := txscript.ComputeTaprootOutputKey(arkscript.UnspendableKey(), root)
	want, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, pkScript) {
		return fmt.Errorf("control block does not match prevout")
	}
	return nil
}

func firstLeafPub(leaf []byte) []byte {
	c, err := arkscript.DecodeClosure(leaf)
	if err != nil {
		return nil
	}
	switch t := c.(type) {
	case *arkscript.MultisigClosure:
		if len(t.PubKeys) > 0 && t.PubKeys[0] != nil {
			return schnorr.SerializePubKey(t.PubKeys[0])
		}
	}
	return nil
}

func requireExactLeaf(in psbt.PInput, pkScript, wantLeaf, wantControl []byte, allowed [][]byte) error {
	return requireExactLeafWithSighash(in, pkScript, wantLeaf, wantControl, allowed, txscript.SigHashDefault)
}

func requireExactLeafWithSighash(in psbt.PInput, pkScript, wantLeaf, wantControl []byte, allowed [][]byte, wantSigHash txscript.SigHashType) error {
	if in.WitnessUtxo == nil {
		return fmt.Errorf("witness utxo required")
	}
	if !bytes.Equal(in.WitnessUtxo.PkScript, pkScript) {
		return fmt.Errorf("input script")
	}
	if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("exactly one tapleaf required")
	}
	if in.SighashType != wantSigHash {
		return fmt.Errorf("unexpected input sighash")
	}
	leaf := in.TaprootLeafScript[0]
	if leaf.LeafVersion != txscript.BaseLeafVersion {
		return fmt.Errorf("tapleaf version")
	}
	if !bytes.Equal(leaf.Script, wantLeaf) {
		return fmt.Errorf("unexpected tapleaf")
	}
	if err := controlBlockMatches(pkScript, leaf.Script, leaf.ControlBlock); err != nil {
		return err
	}
	if len(wantControl) > 0 && !bytes.Equal(leaf.ControlBlock, wantControl) {
		return fmt.Errorf("unexpected control block")
	}
	leafHash := txscript.NewBaseTapLeaf(leaf.Script).TapHash()
	for _, sig := range in.TaprootScriptSpendSig {
		if sig == nil {
			return fmt.Errorf("nil signature")
		}
		if sig.SigHash != wantSigHash {
			return fmt.Errorf("unexpected sighash")
		}
		if !bytes.Equal(sig.LeafHash, leafHash[:]) {
			return fmt.Errorf("signature leaf hash")
		}
		ok := false
		for _, pub := range allowed {
			if bytes.Equal(sig.XOnlyPubKey, pub) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("unexpected signature")
		}
	}
	return nil
}

func requireVerifiedUserSignature(ptx *psbt.Packet, idx int, user, leaf []byte) error {
	return requireVerifiedUserSignatureWithSighash(ptx, idx, user, leaf, txscript.SigHashDefault)
}

func requireVerifiedUserSignatureWithSighash(ptx *psbt.Packet, idx int, user, leaf []byte, wantSigHash txscript.SigHashType) error {
	if ptx == nil || idx < 0 || idx >= len(ptx.Inputs) {
		return fmt.Errorf("user signature required")
	}
	if len(user) != 32 {
		return fmt.Errorf("user pubkey")
	}
	in := ptx.Inputs[idx]
	if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("user signature required")
	}
	leafHash := txscript.NewBaseTapLeaf(leaf).TapHash()
	found := 0
	for _, sig := range in.TaprootScriptSpendSig {
		if sig == nil {
			return fmt.Errorf("nil signature")
		}
		if !bytes.Equal(sig.XOnlyPubKey, user) {
			return fmt.Errorf("unexpected signature")
		}
		if sig.SigHash != wantSigHash || !bytes.Equal(sig.LeafHash, leafHash[:]) {
			return fmt.Errorf("unexpected sighash")
		}
		if err := verifySchnorrOnInputWithSighash(ptx, idx, sig.Signature, user, leaf, wantSigHash); err != nil {
			return fmt.Errorf("user signature invalid")
		}
		found++
	}
	if found != 1 {
		return fmt.Errorf("user signature required")
	}
	return nil
}

func checkpointDestScript(unroll, spendLeaf []byte) ([]byte, []byte, error) {
	unrollClosure, err := arkscript.DecodeClosure(unroll)
	if err != nil {
		return nil, nil, fmt.Errorf("checkpoint tapscript")
	}
	spendClosure, err := arkscript.DecodeClosure(spendLeaf)
	if err != nil {
		return nil, nil, fmt.Errorf("spend leaf")
	}
	tree := &arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{unrollClosure, spendClosure}}
	tapKey, tapTree, err := tree.TapTree()
	if err != nil {
		return nil, nil, err
	}
	pk, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return nil, nil, err
	}
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(spendLeaf).TapHash())
	if err != nil {
		return nil, nil, err
	}
	return pk, proof.ControlBlock, nil
}

func verifyCheckpointPSBT(ptx *psbt.Packet, in policy.VtxoOperationInput, op policy.VtxoOperation, tree *vtxoPolicyTree) error {
	if ptx == nil || ptx.UnsignedTx == nil || tree == nil {
		return fmt.Errorf("checkpoint psbt")
	}
	if ptx.UnsignedTx.Version != 3 || ptx.UnsignedTx.LockTime != 0 {
		return fmt.Errorf("checkpoint version/locktime")
	}
	if len(ptx.UnsignedTx.TxIn) != 1 || len(ptx.Inputs) != 1 {
		return fmt.Errorf("checkpoint must spend one reserved input")
	}
	if ptx.UnsignedTx.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		return fmt.Errorf("checkpoint sequence")
	}
	if _, ok := matchReservedOutpoint(map[string]policy.VtxoOperationInput{
		outpointKey(in.Txid, uint32(in.Vout)): in,
	}, ptx.UnsignedTx.TxIn[0].PreviousOutPoint); !ok {
		return fmt.Errorf("checkpoint outpoint")
	}
	wu := ptx.Inputs[0].WitnessUtxo
	if wu == nil || uint64(wu.Value) != uint64(in.ValueSats) {
		return fmt.Errorf("checkpoint value")
	}
	if !bytes.Equal(wu.PkScript, tree.PkScript) || (len(in.Script) > 0 && !bytes.Equal(wu.PkScript, in.Script)) {
		return fmt.Errorf("checkpoint script")
	}
	if len(op.CheckpointTapscript) == 0 {
		return fmt.Errorf("checkpoint tapscript required")
	}
	user := firstLeafPub(tree.SpendLeaf)
	if err := requireExactLeaf(ptx.Inputs[0], tree.PkScript, tree.SpendLeaf, tree.SpendControl, [][]byte{user}); err != nil {
		return err
	}
	if err := requireVerifiedUserSignature(ptx, 0, user, tree.SpendLeaf); err != nil {
		return err
	}
	dest, _, err := checkpointDestScript(op.CheckpointTapscript, tree.SpendLeaf)
	if err != nil {
		return err
	}
	if len(ptx.UnsignedTx.TxOut) != 2 {
		return fmt.Errorf("checkpoint output count")
	}
	if !bytes.Equal(ptx.UnsignedTx.TxOut[0].PkScript, dest) || uint64(ptx.UnsignedTx.TxOut[0].Value) != uint64(in.ValueSats) {
		return fmt.Errorf("checkpoint dest")
	}
	if !bytes.Equal(ptx.UnsignedTx.TxOut[1].PkScript, txutils.ANCHOR_PKSCRIPT) || ptx.UnsignedTx.TxOut[1].Value != 0 {
		return fmt.Errorf("checkpoint p2a")
	}
	return nil
}

func verifySpendPSBT(ptx *psbt.Packet, op policy.VtxoOperation, inputs []policy.VtxoOperationInput, tree *vtxoPolicyTree, checkpoints []*psbt.Packet) error {
	if ptx == nil || ptx.UnsignedTx == nil || tree == nil {
		return fmt.Errorf("psbt required")
	}
	if len(inputs) != 1 || len(checkpoints) != 1 {
		return fmt.Errorf("exact spend program requires one input")
	}
	if ptx.UnsignedTx.Version != 3 || ptx.UnsignedTx.LockTime != 0 {
		return fmt.Errorf("ark tx version/locktime")
	}
	if len(ptx.UnsignedTx.TxIn) != 1 || len(ptx.Inputs) != 1 {
		return fmt.Errorf("ark input count")
	}
	if ptx.UnsignedTx.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		return fmt.Errorf("ark input sequence")
	}
	cp := checkpoints[0]
	if cp == nil || cp.UnsignedTx == nil {
		return fmt.Errorf("checkpoint psbt")
	}
	wantOutpoint := wire.OutPoint{Hash: cp.UnsignedTx.TxHash(), Index: 0}
	if ptx.UnsignedTx.TxIn[0].PreviousOutPoint != wantOutpoint {
		return fmt.Errorf("ark input is not the checkpoint")
	}
	destScript, arkControl, err := checkpointDestScript(op.CheckpointTapscript, tree.SpendLeaf)
	if err != nil {
		return err
	}
	wu := ptx.Inputs[0].WitnessUtxo
	if wu == nil || uint64(wu.Value) != uint64(inputs[0].ValueSats) || !bytes.Equal(wu.PkScript, destScript) {
		return fmt.Errorf("ark prevout")
	}
	user := firstLeafPub(tree.SpendLeaf)
	if err := requireExactLeaf(ptx.Inputs[0], destScript, tree.SpendLeaf, arkControl, [][]byte{user}); err != nil {
		return err
	}
	if err := requireVerifiedUserSignature(ptx, 0, user, tree.SpendLeaf); err != nil {
		return err
	}
	if len(ptx.UnsignedTx.TxOut) != 3 {
		return fmt.Errorf("ark output count")
	}
	dest := ptx.UnsignedTx.TxOut[0]
	change := ptx.UnsignedTx.TxOut[1]
	anchor := ptx.UnsignedTx.TxOut[2]
	if uint64(dest.Value) != uint64(op.AmountSats) || !bytes.Equal(dest.PkScript, op.DestScript) {
		return fmt.Errorf("dest")
	}
	if dest.Value < program.DustSats || dest.Value > program.TxRecipientCapSats {
		return fmt.Errorf("dest amount")
	}
	if !bytes.Equal(change.PkScript, tree.PkScript) || !bytes.Equal(change.PkScript, op.ChangeScript) {
		return fmt.Errorf("change must be vault-policy-v1")
	}
	if change.Value < program.DustSats {
		return fmt.Errorf("change below dust")
	}
	if !bytes.Equal(anchor.PkScript, txutils.ANCHOR_PKSCRIPT) || anchor.Value != 0 {
		return fmt.Errorf("p2a output")
	}
	inSum := uint64(wu.Value)
	outSum := uint64(dest.Value + change.Value + anchor.Value)
	if inSum != outSum {
		return fmt.Errorf("input/output conservation")
	}
	if op.FeeSats != 0 {
		return fmt.Errorf("fee mismatch")
	}
	return nil
}

func unsignedPSBTEqual(a, b *psbt.Packet) bool {
	if a == nil || b == nil || a.UnsignedTx == nil || b.UnsignedTx == nil {
		return false
	}
	if a.UnsignedTx.Version != b.UnsignedTx.Version || a.UnsignedTx.LockTime != b.UnsignedTx.LockTime {
		return false
	}
	if a.UnsignedTx.TxHash() != b.UnsignedTx.TxHash() {
		return false
	}
	if len(a.Inputs) != len(b.Inputs) || len(a.UnsignedTx.TxIn) != len(b.UnsignedTx.TxIn) {
		return false
	}
	for i := range a.Inputs {
		if a.UnsignedTx.TxIn[i].Sequence != b.UnsignedTx.TxIn[i].Sequence {
			return false
		}
		if a.Inputs[i].SighashType != b.Inputs[i].SighashType {
			return false
		}
		aw, bw := a.Inputs[i].WitnessUtxo, b.Inputs[i].WitnessUtxo
		if aw == nil || bw == nil || aw.Value != bw.Value || !bytes.Equal(aw.PkScript, bw.PkScript) {
			return false
		}
		if len(a.Inputs[i].TaprootLeafScript) != 1 || len(b.Inputs[i].TaprootLeafScript) != 1 {
			return false
		}
		al, bl := a.Inputs[i].TaprootLeafScript[0], b.Inputs[i].TaprootLeafScript[0]
		if al == nil || bl == nil || al.LeafVersion != bl.LeafVersion ||
			!bytes.Equal(al.Script, bl.Script) || !bytes.Equal(al.ControlBlock, bl.ControlBlock) {
			return false
		}
		if len(a.Inputs[i].TaprootScriptSpendSig) != len(b.Inputs[i].TaprootScriptSpendSig) {
			return false
		}
		for j := range a.Inputs[i].TaprootScriptSpendSig {
			as, bs := a.Inputs[i].TaprootScriptSpendSig[j], b.Inputs[i].TaprootScriptSpendSig[j]
			if as == nil || bs == nil || as.SigHash != bs.SigHash ||
				!bytes.Equal(as.XOnlyPubKey, bs.XOnlyPubKey) || !bytes.Equal(as.LeafHash, bs.LeafHash) ||
				!bytes.Equal(as.Signature, bs.Signature) {
				return false
			}
		}
	}
	return true
}
