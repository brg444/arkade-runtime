package allowancedraft

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// Native construction fixtures exercise stock builders, checkpoint linkage,
// signatures, intent proofs and batch-leaf construction. They create no daemon
// or admitted state, and cannot establish settlement or recovery liveness.
type nativeFixture struct {
	*fixture
	genesis, boot  *psbt.Packet
	bootCheckpoint *psbt.Packet
	expect         BootstrapExpectation
	issuer         scriptlib.TapscriptsVtxoScript
	exit           []byte
}

func privateKey(n byte) *btcec.PrivateKey {
	key, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{n}, 32))
	return key
}

func appendPackets(t *testing.T, p *psbt.Packet, packets ...extension.Packet) {
	t.Helper()
	ext, err := extension.NewExtensionFromPackets(packets...)
	check(t, err)
	raw, err := ext.Serialize()
	check(t, err)
	p.UnsignedTx.AddTxOut(wire.NewTxOut(0, raw))
	p.Outputs = append(p.Outputs, psbt.POutput{})
}

func vtxoInput(t *testing.T, prev *wire.MsgTx, vout uint32, contract scriptlib.TapscriptsVtxoScript, leaf []byte) offchain.VtxoInput {
	t.Helper()
	_, tree, err := contract.TapTree()
	check(t, err)
	proof, err := tree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leaf).TapHash())
	check(t, err)
	cb, err := txscript.ParseControlBlock(proof.ControlBlock)
	check(t, err)
	revealed, err := contract.Encode()
	check(t, err)
	return offchain.VtxoInput{Outpoint: &wire.OutPoint{Hash: prev.TxHash(), Index: vout}, Amount: prev.TxOut[vout].Value, Tapscript: &waddrmgr.Tapscript{ControlBlock: cb, RevealedScript: proof.Script}, RevealedTapscripts: revealed}
}

func (n *nativeFixture) contract() scriptlib.TapscriptsVtxoScript {
	closures := make([]scriptlib.Closure, 0, 2)
	for _, leaf := range n.leaves {
		c, err := scriptlib.DecodeClosure(leaf.Script)
		check(n.t, err)
		closures = append(closures, c)
	}
	return scriptlib.TapscriptsVtxoScript{Closures: closures}
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	n := &nativeFixture{}
	n.issuer = *scriptlib.NewDefaultVtxoScript(testKey(7), testKey(4), arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 32})
	issuerKey, _, err := n.issuer.TapTree()
	check(t, err)
	issuerScript, err := scriptlib.P2TRScript(issuerKey)
	check(t, err)
	issuerLeaf, err := n.issuer.ForfeitClosures()[0].Script()
	check(t, err)
	n.exit, err = (&scriptlib.CSVMultisigClosure{MultisigClosure: scriptlib.MultisigClosure{PubKeys: []*btcec.PublicKey{testKey(4)}}, Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 10}}).Script()
	check(t, err)
	// The initial funding output is a fixture. Every later controller identity
	// and asset ownership record is derived from its actual transaction chain.
	funding := wire.NewMsgTx(3)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{77}}, nil, nil))
	funding.AddTxOut(wire.NewTxOut(30000, issuerScript))
	n.genesis, _, err = offchain.BuildTxs([]offchain.VtxoInput{vtxoInput(t, funding, 0, n.issuer, issuerLeaf)}, []*wire.TxOut{wire.NewTxOut(ControllerSats, issuerScript), wire.NewTxOut(30000-ControllerSats, issuerScript)}, n.exit)
	check(t, err)
	issue := asset.Packet{{Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}}}}
	appendPackets(t, n.genesis, issue)
	n.fixture = newFixtureForController(t, asset.AssetId{Txid: n.genesis.UnsignedTx.TxHash(), Index: 0})
	check(t, asset.ValidateAssetTransaction(context.Background(), n.genesis.UnsignedTx, issue, nil, n))
	var cps []*psbt.Packet
	n.boot, cps, err = offchain.BuildTxs([]offchain.VtxoInput{vtxoInput(t, n.genesis.UnsignedTx, 0, n.issuer, issuerLeaf)}, []*wire.TxOut{wire.NewTxOut(ControllerSats, n.pkScript)}, n.exit)
	check(t, err)
	n.bootCheckpoint = cps[0]
	initial, err := (State{n.p.Budget, 0}).Packet()
	check(t, err)
	appendPackets(t, n.boot, n.markerPacket(0), initial)
	check(t, txutils.SetArkPsbtField(n.boot, 0, arkade.PrevArkTxField, *n.genesis.UnsignedTx))
	n.expect = BootstrapExpectation{ControllerID: n.p.ControllerID, Budget: n.p.Budget, IssuerScript: issuerScript, ContractScript: n.pkScript, CheckpointTapscript: n.exit}
	op, err := ValidateBootstrap(n.genesis.UnsignedTx, n.boot, n.bootCheckpoint, n.expect)
	check(t, err)
	check(t, asset.ValidateAssetTransaction(context.Background(), n.boot.UnsignedTx, n.markerPacket(0), map[int][]asset.Asset{0: {{AssetId: n.p.ControllerID.String(), Amount: 1}}}, n))
	n.prev[n.boot.UnsignedTx.TxHash()] = n.boot.UnsignedTx.Copy()
	n.assets[op] = []asset.Asset{{AssetId: n.p.ControllerID.String(), Amount: 1}}
	signPacket(t, n.boot, privateKey(7), privateKey(4))
	signPacket(t, n.bootCheckpoint, privateKey(7), privateKey(4))
	return n
}

func signPacket(t *testing.T, p *psbt.Packet, keys ...*btcec.PrivateKey) {
	t.Helper()
	fetch, err := txutils.GetPrevOutputFetcher(p)
	check(t, err)
	hashes := txscript.NewTxSigHashes(p.UnsignedTx, fetch)
	for i, input := range p.Inputs {
		if len(input.TaprootLeafScript) != 1 {
			t.Fatal("fixture requires one selected leaf")
		}
		leaf := input.TaprootLeafScript[0]
		tap := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script)
		leafHash := tap.TapHash()
		for _, key := range keys {
			sig, err := txscript.RawTxInTapscriptSignature(p.UnsignedTx, hashes, i, input.WitnessUtxo.Value, input.WitnessUtxo.PkScript, tap, input.SighashType, key)
			check(t, err)
			p.Inputs[i].TaprootScriptSpendSig = append(p.Inputs[i].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()), LeafHash: leafHash[:], Signature: sig[:64], SigHash: input.SighashType})
		}
	}
	verified, err := scriptlib.VerifyTapscriptSigs(p, fetch)
	check(t, err)
	if len(verified) != len(p.Inputs) {
		t.Fatal("not all fixture inputs verified")
	}
}

type nativeFetcher struct {
	txscript.PrevOutputFetcher
	logical map[wire.OutPoint]*wire.MsgTx
	indexes map[wire.OutPoint]uint32
}

func (f nativeFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx { return f.logical[op] }
func (f nativeFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	tx := f.logical[op]
	if tx == nil {
		return nil
	}
	return tx.TxOut[f.indexes[op]].PkScript
}

func (n *nativeFixture) payment(controller, principal wire.OutPoint, remaining int64, seq uint64) (*psbt.Packet, []*psbt.Packet) {
	t := n.t
	contract := n.contract()
	ctrlPrev, moneyPrev := n.prev[controller.Hash], n.prev[principal.Hash]
	inputs := []offchain.VtxoInput{vtxoInput(t, ctrlPrev, controller.Index, contract, n.leaves[0].Script), vtxoInput(t, moneyPrev, principal.Index, contract, n.leaves[0].Script)}
	// This pinned stock builder requires input/output equality. Native fee
	// construction is a separate integration gate; this path uses zero fees.
	ptx, cps, err := offchain.BuildTxs(inputs, []*wire.TxOut{wire.NewTxOut(ControllerSats, n.pkScript), wire.NewTxOut(1000, n.recipientScript), wire.NewTxOut(inputs[1].Amount-1000, n.pkScript)}, n.exit)
	check(t, err)
	state, err := (State{remaining - 1000, seq + 1}).Packet()
	check(t, err)
	appendPackets(t, ptx, n.markerPacket(0), arkade.EmulatorPacket{{Vin: 0, Script: n.scripts.Spend}, {Vin: 1, Script: n.scripts.Spend}}, state)
	check(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevArkTxField, *ctrlPrev))
	check(t, txutils.SetArkPsbtField(ptx, 1, arkade.PrevArkTxField, *moneyPrev))
	return ptx, cps
}

func (n *nativeFixture) executePayment(ptx *psbt.Packet, cps []*psbt.Packet) error {
	base, err := txutils.GetPrevOutputFetcher(ptx)
	if err != nil {
		return err
	}
	fetch := nativeFetcher{PrevOutputFetcher: base, logical: make(map[wire.OutPoint]*wire.MsgTx), indexes: make(map[wire.OutPoint]uint32)}
	if len(cps) != len(ptx.Inputs) {
		return fmt.Errorf("checkpoint count")
	}
	assets := make(map[int][]asset.Asset)
	for i, in := range ptx.UnsignedTx.TxIn {
		original := cps[i].UnsignedTx.TxIn[0].PreviousOutPoint
		prev := n.prev[original.Hash]
		if err := validateCheckpointLink(ptx, i, cps[i], prev, original.Index, n.exit); err != nil {
			return err
		}
		fetch.logical[in.PreviousOutPoint] = prev
		fetch.indexes[in.PreviousOutPoint] = original.Index
		if held := n.assets[original]; len(held) > 0 {
			assets[i] = held
		}
	}
	ext, err := extension.NewExtensionFromTx(ptx.UnsignedTx)
	if err != nil {
		return err
	}
	if err := asset.ValidateAssetTransaction(context.Background(), ptx.UnsignedTx, ext.GetAssetPacket(), assets, n); err != nil {
		return err
	}
	entries, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return err
	}
	budget := arkade.NewComputeBudget()
	for _, entry := range entries {
		script, err := arkade.ReadArkadeScript(ptx, n.emulator, entry)
		if err != nil {
			return err
		}
		if err := script.Execute(ptx.UnsignedTx, fetch, int(entry.Vin), arkade.WithComputeBudget(budget)); err != nil {
			return err
		}
	}
	return nil
}

func (n *nativeFixture) renewalProof(previous *wire.MsgTx) (*intent.Proof, string) {
	t := n.t
	message, err := (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, ValidAt: time.Now().Unix() - 60, ExpireAt: time.Now().Unix() + 3600, CosignersPublicKeys: []string{hex.EncodeToString(n.p.DelegatePubkey)}}).Encode()
	check(t, err)
	inputs := []intent.Input{}
	outputs := []*wire.TxOut{}
	for _, vout := range []uint32{0, 2} {
		inputs = append(inputs, intent.Input{OutPoint: &wire.OutPoint{Hash: previous.TxHash(), Index: vout}, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: previous.TxOut[vout]})
		outputs = append(outputs, wire.NewTxOut(previous.TxOut[vout].Value, previous.TxOut[vout].PkScript))
	}
	proof, err := intent.New(message, inputs, outputs)
	check(t, err)
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{n.leaves[1]}
		if i > 0 {
			check(t, txutils.SetArkPsbtField(&proof.Packet, i, arkade.PrevArkTxField, *previous))
		}
	}
	prevExt, err := extension.NewExtensionFromTx(previous)
	check(t, err)
	appendPackets(t, &proof.Packet, n.markerPacket(1), arkade.EmulatorPacket{{Vin: 1, Script: n.scripts.Renew}, {Vin: 2, Script: n.scripts.Renew}}, prevExt.GetPacketByType(StatePacketType))
	base, err := txutils.GetPrevOutputFetcher(&proof.Packet)
	check(t, err)
	fetch := nativeFetcher{PrevOutputFetcher: base, logical: map[wire.OutPoint]*wire.MsgTx{}, indexes: map[wire.OutPoint]uint32{}}
	for i := 1; i < len(proof.Inputs); i++ {
		op := proof.UnsignedTx.TxIn[i].PreviousOutPoint
		fetch.logical[op] = previous
		fetch.indexes[op] = op.Index
	}
	budget := arkade.NewComputeBudget()
	for i := 1; i < len(proof.Inputs); i++ {
		script, err := arkade.ReadArkadeScript(&proof.Packet, n.emulator, arkade.EmulatorEntry{Vin: uint16(i), Script: n.scripts.Renew})
		check(t, err)
		check(t, script.Execute(proof.UnsignedTx, fetch, i, arkade.WithComputeBudget(budget), arkade.WithIntentMessage(message), arkade.WithExpiry(time.Now().Unix()+n.p.RenewalWindow-3600)))
	}
	key := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(n.scripts.Renew))
	signPacket(t, &proof.Packet, key, privateKey(4))
	encoded, err := proof.B64Encode()
	check(t, err)
	check(t, intent.Verify(encoded, message, nil))
	return proof, message
}

func TestNativeBootstrapAndCheckpointSpend(t *testing.T) {
	n := newNativeFixture(t)
	ctrl := wire.OutPoint{Hash: n.boot.UnsignedTx.TxHash(), Index: 0}
	principal := n.previous(20000, nil, false)
	ptx, cps := n.payment(ctrl, principal, 10000, 0)
	check(t, n.executePayment(ptx, cps))
	if bytes.Equal(ptx.Inputs[0].WitnessUtxo.PkScript, n.pkScript) {
		t.Fatal("fixture failed to insert a distinct checkpoint tree")
	}
	key := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(n.scripts.Spend))
	signPacket(t, ptx, privateKey(1), privateKey(2), key, privateKey(4))
	for _, cp := range cps {
		signPacket(t, cp, privateKey(1), privateKey(2), key, privateKey(4))
	}
}

func TestNativeRenewalMessageBinding(t *testing.T) {
	n := newNativeFixture(t)
	p, cps := n.payment(wire.OutPoint{Hash: n.boot.UnsignedTx.TxHash(), Index: 0}, n.previous(20000, nil, false), 10000, 0)
	check(t, n.executePayment(p, cps))
	proof, message := n.renewalProof(p.UnsignedTx)
	encoded, err := proof.B64Encode()
	check(t, err)
	if err := intent.Verify(encoded, strings.Replace(message, "register", "delete", 1), nil); err == nil {
		t.Fatal("substituted message accepted")
	}
	proof.UnsignedTx.TxOut[0].Value++
	encoded, err = proof.B64Encode()
	check(t, err)
	if err := intent.Verify(encoded, message, nil); err == nil {
		t.Fatal("substituted output accepted")
	}
}

func TestBatchLeafConstructionContinuesAllowance(t *testing.T) {
	n := newNativeFixture(t)
	p, cps := n.payment(wire.OutPoint{Hash: n.boot.UnsignedTx.TxHash(), Index: 0}, n.previous(20000, nil, false), 10000, 0)
	check(t, n.executePayment(p, cps))
	proof, _ := n.renewalProof(p.UnsignedTx)
	ext, err := extension.NewExtensionFromTx(proof.UnsignedTx)
	check(t, err)
	// This reproduces the explicit packet mapping in arkd's registration
	// application using stock serializers. It is a construction test, not a
	// call to that application or evidence that a server persisted the packet.
	leafExt := extension.Extension{}
	for _, packet := range ext {
		if assets, ok := packet.(asset.Packet); ok {
			leafExt = append(leafExt, assets.LeafTxPacket(proof.UnsignedTx.TxHash()))
		} else {
			leafExt = append(leafExt, packet)
		}
	}
	raw, err := leafExt.Serialize()
	check(t, err)
	outputs := []tree.LeafOutput{}
	for _, output := range proof.UnsignedTx.TxOut[:2] {
		outputs = append(outputs, tree.LeafOutput{Amount: uint64(output.Value), Script: hex.EncodeToString(output.PkScript)})
	}
	outputs = append(outputs, tree.LeafOutput{Amount: 0, Script: hex.EncodeToString(raw)})
	// Root funding and tree signatures are deliberately outside this fixture.
	vt, err := tree.BuildVtxoTree(&wire.OutPoint{Hash: chainhash.Hash{88}}, []tree.Leaf{{Outputs: outputs, CosignersPublicKeys: []string{hex.EncodeToString(n.p.DelegatePubkey)}}}, nil, arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 32})
	check(t, err)
	check(t, vt.Validate())
	leaves := vt.Leaves()
	if len(leaves) != 1 {
		t.Fatal("expected one grouped intent leaf")
	}
	leaf := leaves[0].UnsignedTx
	actualExt, err := extension.NewExtensionFromTx(leaf)
	check(t, err)
	want, err := ext.GetPacketByType(StatePacketType).Serialize()
	check(t, err)
	got, err := actualExt.GetPacketByType(StatePacketType).Serialize()
	check(t, err)
	if !bytes.Equal(want, got) {
		t.Fatal("batch construction changed allowance state")
	}
	group := actualExt.GetAssetPacket()[0]
	if group.Inputs[0].Type != asset.AssetInputTypeIntent || group.Inputs[0].Txid != proof.UnsignedTx.TxHash() {
		t.Fatal("lost intent asset ancestry")
	}
	n.prev[leaf.TxHash()] = leaf.Copy()
	ctrl := wire.OutPoint{Hash: leaf.TxHash(), Index: 0}
	money := wire.OutPoint{Hash: leaf.TxHash(), Index: 1}
	n.assets[ctrl] = []asset.Asset{{AssetId: n.p.ControllerID.String(), Amount: 1}}
	next, cps := n.payment(ctrl, money, 9000, 1)
	check(t, n.executePayment(next, cps))
	// Resetting the state packet in the next spend cannot restore the budget.
	nextExt, err := extension.NewExtensionFromTx(next.UnsignedTx)
	check(t, err)
	for i, packet := range nextExt {
		if packet.Type() == StatePacketType {
			nextExt[i] = extension.UnknownPacket{PacketType: StatePacketType, Data: encoded(t, State{9000, 2})}
		}
	}
	bad, err := nextExt.Serialize()
	check(t, err)
	next.UnsignedTx.TxOut[len(next.UnsignedTx.TxOut)-1].PkScript = bad
	if err := n.executePayment(next, cps); err == nil {
		t.Fatal("post-renewal allowance refill accepted")
	}
}
