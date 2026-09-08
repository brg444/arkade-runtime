package rolling

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// BootstrapExpectation is trusted enrollment context, reconstructed independently
// of the submitted transaction. Validation here establishes structure and hash
// linkage only; admitted issuance, single-spend status and signatures are external
// prerequisites. The result must never activate an enrollment on its own.
type BootstrapExpectation struct {
	ControllerID        asset.AssetId
	Budget              int64
	IssuerScript        []byte
	ContractScript      []byte
	CheckpointTapscript []byte
}

// ValidateBootstrap checks a one-unit, non-reissuable genesis followed by its
// zero-fee native checkpoint transfer into the expected rolling-allowance contract.
func ValidateBootstrap(genesis *wire.MsgTx, transfer, checkpoint *psbt.Packet, expected BootstrapExpectation) (wire.OutPoint, error) {
	fail := func(reason string) (wire.OutPoint, error) {
		return wire.OutPoint{}, fmt.Errorf("allowance bootstrap: %s", reason)
	}
	if !wellFormedTx(genesis) || transfer == nil || !wellFormedTx(transfer.UnsignedTx) || checkpoint == nil || !wellFormedTx(checkpoint.UnsignedTx) {
		return fail("missing transaction")
	}
	if expected.Budget < ControllerSats || expected.Budget > MaxBudget || expected.ControllerID.Index != 0 ||
		!txscript.IsPayToTaproot(expected.IssuerScript) || !txscript.IsPayToTaproot(expected.ContractScript) {
		return fail("invalid enrollment expectation")
	}
	if genesis.TxHash() != expected.ControllerID.Txid || genesis.Version != 3 || len(genesis.TxIn) == 0 || len(genesis.TxOut) == 0 {
		return fail("genesis identity or shape")
	}
	if genesis.TxOut[0].Value != ControllerSats || !bytes.Equal(genesis.TxOut[0].PkScript, expected.IssuerScript) {
		return fail("genesis owner or value")
	}
	genExt, err := extension.NewExtensionFromTx(genesis)
	if err != nil {
		return fail("missing genesis extension")
	}
	groups := genExt.GetAssetPacket()
	if len(genExt) != 1 || len(groups) != 1 {
		return fail("genesis packet count")
	}
	g := groups[0]
	if g.AssetId != nil || g.ControlAsset != nil || len(g.Inputs) != 0 || len(g.Metadata) != 0 || len(g.Outputs) != 1 ||
		g.Outputs[0].Type != asset.AssetOutputTypeLocal || g.Outputs[0].Vout != 0 || g.Outputs[0].Amount != 1 {
		return fail("genesis must issue exactly one non-reissuable controller")
	}
	tx := transfer.UnsignedTx
	if len(tx.TxIn) != 1 || len(transfer.Inputs) != 1 || len(tx.TxOut) != 3 || len(transfer.Outputs) != 3 || tx.Version != 3 || tx.LockTime != 0 || tx.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		return fail("transfer shape")
	}
	if tx.TxOut[0].Value != ControllerSats || !bytes.Equal(tx.TxOut[0].PkScript, expected.ContractScript) ||
		!sameOutput(tx.TxOut[2], txutils.AnchorOutput()) || tx.TxOut[1].Value != 0 {
		return fail("transfer destination or value")
	}
	if err := validateCheckpointLink(transfer, 0, checkpoint, genesis, 0, expected.CheckpointTapscript); err != nil {
		return fail(err.Error())
	}
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		return fail("missing transfer extension")
	}
	if len(ext) != 2 {
		return fail("transfer packet count")
	}
	groups = ext.GetAssetPacket()
	if len(groups) != 1 {
		return fail("transfer asset group count")
	}
	g = groups[0]
	if g.AssetId == nil || *g.AssetId != expected.ControllerID || g.ControlAsset != nil || len(g.Metadata) != 0 || len(g.Inputs) != 1 || len(g.Outputs) != 1 {
		return fail("transfer identity")
	}
	if g.Inputs[0].Type != asset.AssetInputTypeLocal || g.Inputs[0].Vin != 0 || g.Inputs[0].Amount != 1 ||
		g.Outputs[0].Type != asset.AssetOutputTypeLocal || g.Outputs[0].Vout != 0 || g.Outputs[0].Amount != 1 {
		return fail("transfer must preserve the single controller")
	}
	pkt := ext.GetPacketByType(StatePacketType)
	if pkt == nil {
		return fail("missing initial state")
	}
	raw, err := pkt.Serialize()
	if err != nil {
		return fail("invalid initial packet")
	}
	state, err := DecodeRollingState(raw)
	if err != nil || state.Remaining != expected.Budget || state.Sequence != 0 || state.Root != EmptyRoots()[HistoryDepth] {
		return fail("initial allowance mismatch")
	}
	return wire.OutPoint{Hash: tx.TxHash(), Index: 0}, nil
}

func sameOutput(a, b *wire.TxOut) bool {
	return a != nil && b != nil && a.Value == b.Value && bytes.Equal(a.PkScript, b.PkScript)
}

func wellFormedTx(tx *wire.MsgTx) bool {
	if tx == nil || len(tx.TxIn) == 0 || len(tx.TxOut) == 0 {
		return false
	}
	for _, input := range tx.TxIn {
		if input == nil {
			return false
		}
	}
	for _, output := range tx.TxOut {
		if output == nil {
			return false
		}
	}
	return true
}

// validateCheckpointLink reconstructs the stock checkpoint tree from its pinned
// exit and selected source leaf, binding both PSBT inputs to the logical VTXO.
// It checks construction; service admission and final signatures remain separate.
func validateCheckpointLink(tx *psbt.Packet, index int, cp *psbt.Packet, previous *wire.MsgTx, vout uint32, checkpointExit []byte) error {
	bad := func(s string) error { return fmt.Errorf("checkpoint: %s", s) }
	if tx == nil || !wellFormedTx(tx.UnsignedTx) || index < 0 || index >= len(tx.Inputs) || index >= len(tx.UnsignedTx.TxIn) || cp == nil || !wellFormedTx(cp.UnsignedTx) || !wellFormedTx(previous) || int(vout) >= len(previous.TxOut) {
		return bad("missing context")
	}
	c := cp.UnsignedTx
	if len(cp.Inputs) != 1 || len(c.TxIn) != 1 || len(cp.Outputs) != 2 || len(c.TxOut) != 2 || c.Version != 3 || c.LockTime != 0 || c.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		return bad("shape")
	}
	logical := wire.OutPoint{Hash: previous.TxHash(), Index: vout}
	if c.TxIn[0].PreviousOutPoint != logical || tx.UnsignedTx.TxIn[index].PreviousOutPoint != (wire.OutPoint{Hash: c.TxHash(), Index: 0}) {
		return bad("outpoint linkage")
	}
	if !sameOutput(cp.Inputs[0].WitnessUtxo, previous.TxOut[vout]) || !sameOutput(tx.Inputs[index].WitnessUtxo, c.TxOut[0]) || c.TxOut[0].Value != previous.TxOut[vout].Value || !sameOutput(c.TxOut[1], txutils.AnchorOutput()) {
		return bad("value or previous output")
	}
	if len(cp.Inputs[0].TaprootLeafScript) != 1 || len(tx.Inputs[index].TaprootLeafScript) != 1 {
		return bad("selected leaf count")
	}
	sourceLeaf, targetLeaf := cp.Inputs[0].TaprootLeafScript[0], tx.Inputs[index].TaprootLeafScript[0]
	if sourceLeaf == nil || targetLeaf == nil || !bytes.Equal(sourceLeaf.Script, targetLeaf.Script) {
		return bad("selected leaf mismatch")
	}
	if err := arkade.VerifyTaprootLeafCommitment(previous.TxOut[vout].PkScript, sourceLeaf); err != nil {
		return bad("source taproot commitment")
	}
	if err := arkade.VerifyTaprootLeafCommitment(c.TxOut[0].PkScript, targetLeaf); err != nil {
		return bad("checkpoint taproot commitment")
	}
	exit := &scriptlib.CSVMultisigClosure{}
	valid, err := exit.Decode(checkpointExit)
	if err != nil || !valid {
		return bad("exit policy")
	}
	closure, err := scriptlib.DecodeClosure(sourceLeaf.Script)
	if err != nil {
		return bad("source closure")
	}
	tree := scriptlib.TapscriptsVtxoScript{Closures: []scriptlib.Closure{exit, closure}}
	key, _, err := tree.TapTree()
	if err != nil {
		return bad("tree reconstruction")
	}
	expectedScript, err := scriptlib.P2TRScript(key)
	if err != nil || !bytes.Equal(c.TxOut[0].PkScript, expectedScript) {
		return bad("unexpected checkpoint tree")
	}
	fields, err := txutils.GetArkPsbtFields(tx, index, arkade.PrevArkTxField)
	if err != nil || len(fields) != 1 || fields[0].TxHash() != previous.TxHash() {
		return bad("previous transaction attachment")
	}
	return nil
}
