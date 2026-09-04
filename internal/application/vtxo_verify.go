package application

import (
	"bytes"
	"fmt"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/vaulted-guardian/internal/policy"
	"github.com/brg444/vaulted-guardian/internal/program"
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
	return requireVerifiedSignersWithSighash(ptx, idx, [][]byte{user}, leaf, wantSigHash)
}

func requireVerifiedSignersWithSighash(ptx *psbt.Packet, idx int, signers [][]byte, leaf []byte, wantSigHash txscript.SigHashType) error {
	if ptx == nil || idx < 0 || idx >= len(ptx.Inputs) {
		return fmt.Errorf("required signatures missing")
	}
	want := make(map[string]struct{}, len(signers))
	for _, signer := range signers {
		if len(signer) != 32 {
			return fmt.Errorf("signer pubkey")
		}
		want[string(signer)] = struct{}{}
	}
	in := ptx.Inputs[idx]
	if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("required signatures missing")
	}
	leafHash := txscript.NewBaseTapLeaf(leaf).TapHash()
	found := make(map[string]struct{}, len(signers))
	for _, sig := range in.TaprootScriptSpendSig {
		if sig == nil {
			return fmt.Errorf("nil signature")
		}
		key := string(sig.XOnlyPubKey)
		if _, ok := want[key]; !ok {
			return fmt.Errorf("unexpected signature")
		}
		if _, duplicate := found[key]; duplicate {
			return fmt.Errorf("duplicate signature")
		}
		if sig.SigHash != wantSigHash || !bytes.Equal(sig.LeafHash, leafHash[:]) {
			return fmt.Errorf("unexpected sighash")
		}
		if err := verifySchnorrOnInputWithSighash(ptx, idx, sig.Signature, sig.XOnlyPubKey, leaf, wantSigHash); err != nil {
			return fmt.Errorf("signature invalid")
		}
		found[key] = struct{}{}
	}
	if len(found) != len(want) {
		return fmt.Errorf("required signatures missing")
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

func verifyUnsignedCheckpointPSBT(ptx *psbt.Packet, in policy.VtxoOperationInput, op policy.VtxoOperation, tree *vtxoPolicyTree) error {
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
	if len(ptx.Inputs[0].TaprootScriptSpendSig) != 0 {
		return fmt.Errorf("checkpoint must be unsigned before submit")
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

func verifySubmittedCheckpointPSBT(ptx *psbt.Packet, in policy.VtxoOperationInput, op policy.VtxoOperation, tree *vtxoPolicyTree) error {
	if err := verifyCheckpointShape(ptx, in, op, tree); err != nil {
		return err
	}
	if tree.ArkdPub == nil {
		return fmt.Errorf("Operator pubkey required")
	}
	user := firstLeafPub(tree.SpendLeaf)
	operator := schnorr.SerializePubKey(tree.ArkdPub)
	if err := requireExactLeaf(ptx.Inputs[0], tree.PkScript, tree.SpendLeaf, tree.SpendControl, [][]byte{user, operator}); err != nil {
		return err
	}
	return requireVerifiedSignersWithSighash(ptx, 0, [][]byte{user, operator}, tree.SpendLeaf, txscript.SigHashDefault)
}

func verifyCheckpointShape(ptx *psbt.Packet, in policy.VtxoOperationInput, op policy.VtxoOperation, tree *vtxoPolicyTree) error {
	if ptx == nil || ptx.UnsignedTx == nil || tree == nil || len(ptx.Inputs) != 1 {
		return fmt.Errorf("checkpoint psbt")
	}
	clone, err := clonePacket(ptx)
	if err != nil {
		return fmt.Errorf("checkpoint psbt")
	}
	clone.Inputs[0].TaprootScriptSpendSig = nil
	return verifyUnsignedCheckpointPSBT(clone, in, op, tree)
}

func sameUnsignedPSBT(a, b *psbt.Packet) bool {
	if a == nil || b == nil {
		return false
	}
	ac, err := clonePacket(a)
	if err != nil {
		return false
	}
	bc, err := clonePacket(b)
	if err != nil {
		return false
	}
	for i := range ac.Inputs {
		ac.Inputs[i].TaprootScriptSpendSig = nil
	}
	for i := range bc.Inputs {
		bc.Inputs[i].TaprootScriptSpendSig = nil
	}
	return unsignedPSBTEqual(ac, bc)
}

func verifySpendPSBT(ptx *psbt.Packet, op policy.VtxoOperation, inputs []policy.VtxoOperationInput, tree *vtxoPolicyTree, checkpoints []*psbt.Packet) error {
	if ptx == nil || ptx.UnsignedTx == nil || tree == nil {
		return fmt.Errorf("psbt required")
	}
	if len(inputs) == 0 || len(inputs) > maxVtxoSpendInputs || len(checkpoints) != len(inputs) {
		return fmt.Errorf("ark input count")
	}
	if ptx.UnsignedTx.Version != 3 || ptx.UnsignedTx.LockTime != 0 {
		return fmt.Errorf("ark tx version/locktime")
	}
	if len(ptx.UnsignedTx.TxIn) != len(inputs) || len(ptx.Inputs) != len(inputs) {
		return fmt.Errorf("ark input count")
	}
	destScript, arkControl, err := checkpointDestScript(op.CheckpointTapscript, tree.SpendLeaf)
	if err != nil {
		return err
	}
	user := firstLeafPub(tree.SpendLeaf)
	var inSum uint64
	for i, input := range inputs {
		if ptx.UnsignedTx.TxIn[i].Sequence != wire.MaxTxInSequenceNum {
			return fmt.Errorf("ark input sequence")
		}
		cp := checkpoints[i]
		if cp == nil || cp.UnsignedTx == nil {
			return fmt.Errorf("checkpoint psbt")
		}
		wantOutpoint := wire.OutPoint{Hash: cp.UnsignedTx.TxHash(), Index: 0}
		if ptx.UnsignedTx.TxIn[i].PreviousOutPoint != wantOutpoint {
			return fmt.Errorf("ark input is not checkpoint %d", i)
		}
		wu := ptx.Inputs[i].WitnessUtxo
		if wu == nil || wu.Value < 0 || uint64(wu.Value) != uint64(input.ValueSats) || !bytes.Equal(wu.PkScript, destScript) {
			return fmt.Errorf("ark prevout")
		}
		if uint64(wu.Value) > ^uint64(0)-inSum {
			return fmt.Errorf("input amount overflow")
		}
		inSum += uint64(wu.Value)
		if err := requireExactLeaf(ptx.Inputs[i], destScript, tree.SpendLeaf, arkControl, [][]byte{user}); err != nil {
			return err
		}
		if err := requireVerifiedUserSignature(ptx, i, user, tree.SpendLeaf); err != nil {
			return err
		}
	}
	wantOutputs := 2
	if op.ChangeSats > 0 {
		wantOutputs = 3
	}
	if len(ptx.UnsignedTx.TxOut) != wantOutputs {
		return fmt.Errorf("ark output count")
	}
	dest := ptx.UnsignedTx.TxOut[0]
	anchor := ptx.UnsignedTx.TxOut[len(ptx.UnsignedTx.TxOut)-1]
	if uint64(dest.Value) != uint64(op.AmountSats) || !bytes.Equal(dest.PkScript, op.DestScript) {
		return fmt.Errorf("dest")
	}
	// The authenticated operation was reserved against this vault's immutable
	// recipient cap. Rechecking the release default here would incorrectly
	// override a valid per-vault policy instance.
	if dest.Value < program.DustSats {
		return fmt.Errorf("dest amount")
	}
	var changeValue uint64
	if op.ChangeSats == 0 {
		if op.ChangeVout != nil || len(op.ChangeScript) != 0 {
			return fmt.Errorf("invalid no-change shape")
		}
	} else {
		if op.ChangeVout == nil || *op.ChangeVout != 1 || op.ChangeSats < program.DustSats {
			return fmt.Errorf("invalid change shape")
		}
		change := ptx.UnsignedTx.TxOut[1]
		if !bytes.Equal(change.PkScript, tree.PkScript) || !bytes.Equal(change.PkScript, op.ChangeScript) {
			return fmt.Errorf("change must be vault-policy-v1")
		}
		if change.Value != op.ChangeSats {
			return fmt.Errorf("change amount")
		}
		changeValue = uint64(change.Value)
	}
	if !bytes.Equal(anchor.PkScript, txutils.ANCHOR_PKSCRIPT) || anchor.Value != 0 {
		return fmt.Errorf("p2a output")
	}
	outSum := uint64(dest.Value) + changeValue
	if op.FeeSats < 0 || uint64(op.FeeSats) > ^uint64(0)-outSum || inSum != outSum+uint64(op.FeeSats) {
		return fmt.Errorf("input/output conservation")
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
