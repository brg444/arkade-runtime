package allowancedraft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func encoded(t *testing.T, s State) []byte { t.Helper(); b, e := s.Encode(); return must(t, b, e) }

// Keys, asset history, expiry and prevout resolution here are fixtures. A live
// Operator/indexer must authenticate that context at admission and settlement.
type fixture struct {
	t                         *testing.T
	p                         Parameters
	scripts                   Scripts
	emulator                  *btcec.PublicKey
	pkScript, recipientScript []byte
	leaves                    [2]*psbt.TaprootTapLeafScript
	prev                      map[chainhash.Hash]*wire.MsgTx
	assets                    map[wire.OutPoint][]asset.Asset
	serial                    uint32
	tx                        *wire.MsgTx
	packet                    asset.Packet
	state                     []byte
	renew                     bool
	intent                    string
	expiries                  map[int]int64
}

func testKey(n byte) *btcec.PublicKey {
	_, pub := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{n}, 32))
	return pub
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, emulator: testKey(3), prev: make(map[chainhash.Hash]*wire.MsgTx), assets: make(map[wire.OutPoint][]asset.Asset), expiries: make(map[int]int64)}
	f.p = Parameters{ControllerID: asset.AssetId{Txid: chainhash.Hash{1, 2, 3}, Index: 0}, Budget: 10000, RecipientCap: 5000, FeeCap: 200, DelegatePubkey: testKey(5).SerializeCompressed(), RenewalWindow: 259200}
	var err error
	f.scripts, err = Compile(f.p)
	check(t, err)
	spendKey := arkade.ComputeArkadeScriptPublicKey(f.emulator, arkade.ArkadeScriptHash(f.scripts.Spend))
	renewKey := arkade.ComputeArkadeScriptPublicKey(f.emulator, arkade.ArkadeScriptHash(f.scripts.Renew))
	s, err := (&scriptlib.MultisigClosure{PubKeys: []*btcec.PublicKey{testKey(1), testKey(2), spendKey, testKey(4)}}).Script()
	check(t, err)
	r, err := (&scriptlib.MultisigClosure{PubKeys: []*btcec.PublicKey{renewKey, testKey(4)}}).Script()
	check(t, err)
	// The fixture tree qualifies the two emulator leaves. Production recovery
	// closures and the full Contract Pack are a separate integration gate.
	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(s), txscript.NewBaseTapLeaf(r))
	root := tree.RootNode.TapHash()
	f.pkScript, err = txscript.PayToTaprootScript(txscript.ComputeTaprootOutputKey(scriptlib.UnspendableKey(), root[:]))
	check(t, err)
	for i, proof := range tree.LeafMerkleProofs {
		cb := proof.ToControlBlock(scriptlib.UnspendableKey())
		control, err := cb.ToBytes()
		check(t, err)
		f.leaves[i] = &psbt.TaprootTapLeafScript{Script: proof.Script, LeafVersion: proof.LeafVersion, ControlBlock: control}
	}
	f.recipientScript, err = txscript.PayToTaprootScript(testKey(6))
	check(t, err)
	return f
}

func (f *fixture) markerPacket(input int) asset.Packet {
	return asset.Packet{{AssetId: &f.p.ControllerID, Inputs: []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: uint16(input), Amount: 1}}, Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}}}}
}

func (f *fixture) previous(value int64, state []byte, controller bool) wire.OutPoint {
	f.serial++
	tx := wire.NewMsgTx(3)
	tx.LockTime = f.serial
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{99}, Index: f.serial}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(value, bytes.Clone(f.pkScript)))
	var packets []extension.Packet
	if state != nil {
		packets = append(packets, extension.UnknownPacket{PacketType: StatePacketType, Data: state})
	}
	if controller {
		packets = append(packets, f.markerPacket(0))
	}
	if len(packets) > 0 {
		ext, err := extension.NewExtensionFromPackets(packets...)
		check(f.t, err)
		raw, err := ext.Serialize()
		check(f.t, err)
		tx.AddTxOut(wire.NewTxOut(0, raw))
	}
	f.prev[tx.TxHash()] = tx
	op := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	if controller {
		f.assets[op] = []asset.Asset{{AssetId: f.p.ControllerID.String(), Amount: 1}}
	}
	return op
}

func (f *fixture) spend(old State, values []int64, pay, fee int64) {
	f.renew = false
	f.tx = wire.NewMsgTx(3)
	f.packet = f.markerPacket(0)
	ctrl := f.previous(ControllerSats, encoded(f.t, old), true)
	f.tx.AddTxIn(wire.NewTxIn(&ctrl, nil, nil))
	var total int64
	for _, value := range values {
		op := f.previous(value, nil, false)
		f.tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
		total += value
	}
	f.tx.AddTxOut(wire.NewTxOut(ControllerSats, bytes.Clone(f.pkScript)))
	f.tx.AddTxOut(wire.NewTxOut(pay, bytes.Clone(f.recipientScript)))
	if change := total - pay - fee; change > 0 {
		f.tx.AddTxOut(wire.NewTxOut(change, bytes.Clone(f.pkScript)))
	}
	f.tx.AddTxOut(wire.NewTxOut(0, []byte{txscript.OP_1, 2, 0x4e, 0x73}))
	f.tx.AddTxOut(wire.NewTxOut(0, nil))
	f.state = encoded(f.t, State{Remaining: old.Remaining - pay - fee, Sequence: old.Sequence + 1})
	f.repack()
}

func (f *fixture) renewal(old State, values []int64) {
	f.renew = true
	f.tx = wire.NewMsgTx(2)
	f.packet = f.markerPacket(1)
	synthetic := f.previous(0, nil, false)
	f.tx.AddTxIn(wire.NewTxIn(&synthetic, nil, nil))
	ctrl := f.previous(ControllerSats, encoded(f.t, old), true)
	f.tx.AddTxIn(wire.NewTxIn(&ctrl, nil, nil))
	f.tx.AddTxOut(wire.NewTxOut(ControllerSats, bytes.Clone(f.pkScript)))
	for _, value := range values {
		op := f.previous(value, nil, false)
		f.tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
		f.tx.AddTxOut(wire.NewTxOut(value, bytes.Clone(f.pkScript)))
	}
	f.tx.AddTxOut(wire.NewTxOut(0, nil))
	f.state = encoded(f.t, old)
	message, err := json.Marshal(map[string]any{"type": "register", "onchain_output_indexes": []int{}, "cosigners_public_keys": []string{fmt.Sprintf("%x", f.p.DelegatePubkey)}})
	check(f.t, err)
	f.intent = string(message)
	for i := 1; i < len(f.tx.TxIn); i++ {
		f.expiries[i] = time.Now().Unix() + f.p.RenewalWindow - 3600
	}
	f.repack()
}

func (f *fixture) repack() {
	first := 0
	code := f.scripts.Spend
	if f.renew {
		first = 1
		code = f.scripts.Renew
	}
	var entries arkade.EmulatorPacket
	for i := first; i < len(f.tx.TxIn); i++ {
		entries = append(entries, arkade.EmulatorEntry{Vin: uint16(i), Script: code})
	}
	packets := []extension.Packet{entries}
	if len(f.packet) > 0 {
		packets = append(packets, f.packet)
	}
	if f.state != nil {
		packets = append(packets, extension.UnknownPacket{PacketType: StatePacketType, Data: f.state})
	}
	ext, err := extension.NewExtensionFromPackets(packets...)
	check(f.t, err)
	raw, err := ext.Serialize()
	check(f.t, err)
	f.tx.TxOut[len(f.tx.TxOut)-1].PkScript = raw
}

func (f *fixture) FetchPrevOutput(op wire.OutPoint) *wire.TxOut {
	tx := f.prev[op.Hash]
	if tx == nil || int(op.Index) >= len(tx.TxOut) {
		return nil
	}
	return tx.TxOut[op.Index]
}
func (f *fixture) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx { return f.prev[op.Hash] }
func (f *fixture) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if out := f.FetchPrevOutput(op); out != nil {
		return out.PkScript
	}
	return nil
}
func (f *fixture) AssetExists(_ context.Context, id string) bool {
	return id == f.p.ControllerID.String()
}
func (f *fixture) GetControlAsset(context.Context, string) (string, error) {
	return "", fmt.Errorf("fixture controller has no reissuance authority")
}

func (f *fixture) validateAssets() error {
	prev := make(map[int][]asset.Asset)
	for i, in := range f.tx.TxIn {
		if assets := f.assets[in.PreviousOutPoint]; len(assets) > 0 {
			prev[i] = assets
		}
	}
	return asset.ValidateAssetTransaction(context.Background(), f.tx, f.packet, prev, f)
}

func (f *fixture) evaluate(checkAssets bool, budget *arkade.ComputeBudget) error {
	f.repack()
	if checkAssets {
		if err := f.validateAssets(); err != nil {
			return fmt.Errorf("asset provenance: %w", err)
		}
	}
	ptx, err := psbt.NewFromUnsignedTx(f.tx)
	if err != nil {
		return err
	}
	first, leaf := 0, 0
	code := f.scripts.Spend
	if f.renew {
		first, leaf = 1, 1
		code = f.scripts.Renew
	}
	if budget == nil {
		budget = arkade.NewComputeBudget()
	}
	for i := first; i < len(f.tx.TxIn); i++ {
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.leaves[leaf]}
		prevout := f.FetchPrevOutput(f.tx.TxIn[i].PreviousOutPoint)
		if prevout == nil {
			return fmt.Errorf("missing previous output %d", i)
		}
		ptx.Inputs[i].WitnessUtxo = prevout
		if err := arkade.VerifyTaprootLeafCommitment(prevout.PkScript, f.leaves[leaf]); err != nil {
			return err
		}
		script, err := arkade.ReadArkadeScript(ptx, f.emulator, arkade.EmulatorEntry{Vin: uint16(i), Script: code})
		if err != nil {
			return err
		}
		opts := []arkade.ExecuteOption{arkade.WithComputeBudget(budget)}
		if f.renew {
			opts = append(opts, arkade.WithIntentMessage(f.intent))
			if expiry, ok := f.expiries[i]; ok {
				opts = append(opts, arkade.WithExpiry(expiry))
			}
		}
		if err := script.Execute(f.tx, f, i, opts...); err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
	}
	return nil
}
