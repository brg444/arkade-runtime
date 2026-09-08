package rolling

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const CleanupLifetimeSeconds int64 = 300

// compileRollingCleanup authorizes only a BIP322 delete message. It cannot
// register, transfer principal or renew an output. Unlike renewal, deletion
// can be freshly authorized after the original registration and source expiry.
// Its own short message expiry bounds replay through the stock Operator API.
// The Guardian must additionally fence the exact persisted attempt before
// signing; script execution alone does not authorize a cleanup generation.
func compileRollingCleanup() ([]byte, error) {
	b := newBuilder()
	b.header(2, 2, MaxMoneyInputs+2)
	b.AddOp(OP_INSPECTNUMOUTPUTS)
	b.eq(1)
	b.inputValue(0)
	b.eq(0)
	b.outputValue(0)
	b.eq(0)
	b.AddInt64(0).AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(-1)
	b.AddOp(OP_DROP)
	b.AddData([]byte("type")).AddOp(OP_INSPECTINTENTMESSAGE).AddOp(OP_VERIFY).AddData([]byte("delete")).AddOp(OP_EQUALVERIFY)
	b.AddData([]byte("expire_at")).AddOp(OP_INSPECTINTENTMESSAGE).AddOp(OP_VERIFY)
	b.bounded(CleanupLifetimeSeconds, 100_000_000_000)
	b.AddInt64(CleanupLifetimeSeconds).AddOp(OP_SUB).AddOp(OP_CHECKTIMEVERIFY)
	for _, packet := range []int64{0, StatePacketType} {
		b.AddInt64(packet).AddOp(OP_INSPECTPACKET).AddOp(OP_NOT).AddOp(OP_VERIFY).AddOp(OP_DROP)
	}
	for i := 1; i <= MaxMoneyInputs+1; i++ {
		b.AddOp(OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(OP_GREATERTHAN).AddOp(OP_IF)
		b.inputScript(i)
		b.inputScript(1)
		b.AddOp(OP_EQUALVERIFY)
		b.inputValue(i)
		b.bounded(ControllerSats, maxMoney)
		b.AddOp(OP_DROP).AddOp(OP_ENDIF)
	}
	b.AddOp(OP_DEPTH)
	b.eq(0)
	b.AddOp(OP_TRUE)
	return b.Script()
}

type Cleanup struct {
	Proof   *intent.Proof
	Message string
}

// BuildCleanup constructs the exact public deletion evidence for the given
// original sources. It neither signs nor releases the controller reservation.
// Only a successful, matched Operator deletion can establish queue cleanup;
// an expired registration, missing match or lost response does not do so.
func BuildCleanup(contract *Contract, sources []Source, validAt, expireAt int64) (*Cleanup, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	if validAt <= 0 || expireAt <= validAt || expireAt > 100_000_000_000 || expireAt-validAt > CleanupLifetimeSeconds {
		return nil, fmt.Errorf("cleanup validity bounds")
	}
	if len(sources) == 0 || len(sources) > MaxMoneyInputs+1 {
		return nil, fmt.Errorf("cleanup source count")
	}
	message, err := (intent.DeleteMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: expireAt}).Encode()
	if err != nil {
		return nil, err
	}
	inputs := make([]intent.Input, len(sources))
	seen := map[wire.OutPoint]bool{}
	for i, s := range sources {
		if !wellFormedTx(s.Previous) || s.Previous.SerializeSize() > 100000 || int(s.Index) >= len(s.Previous.TxOut) {
			return nil, fmt.Errorf("cleanup source missing")
		}
		out := s.Previous.TxOut[s.Index]
		point := wire.OutPoint{Hash: s.Previous.TxHash(), Index: s.Index}
		if seen[point] || !bytes.Equal(out.PkScript, c.PkScript) || out.Value < ControllerSats || out.Value > maxMoney {
			return nil, fmt.Errorf("cleanup source binding")
		}
		seen[point] = true
		inputs[i] = intent.Input{OutPoint: &point, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: wire.NewTxOut(out.Value, bytes.Clone(out.PkScript))}
	}
	proof, err := intent.New(message, inputs, []*wire.TxOut{{Value: 0, PkScript: []byte{txscript.OP_RETURN}}})
	if err != nil {
		return nil, err
	}
	tree, err := c.Tree.Encode()
	if err != nil {
		return nil, err
	}
	entries := arkade.EmulatorPacket{}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{c.Cleanup}
		field, e := txutils.VtxoTaprootTreeField.Encode(tree)
		if e != nil {
			return nil, e
		}
		proof.Inputs[i].Unknowns = append(proof.Inputs[i].Unknowns, field)
		if i > 0 {
			if e = txutils.SetArkPsbtField(&proof.Packet, i, arkade.PrevArkTxField, *sources[i-1].Previous); e != nil {
				return nil, e
			}
			entries = append(entries, arkade.EmulatorEntry{Vin: uint16(i), Script: bytes.Clone(c.Programs.Cleanup)})
		}
	}
	ext, err := extension.NewExtensionFromPackets(entries)
	if err != nil {
		return nil, err
	}
	raw, err := ext.Serialize()
	if err != nil {
		return nil, err
	}
	proof.UnsignedTx.TxOut[0].PkScript = raw
	if err = checkWeight(&proof.Packet); err != nil {
		return nil, err
	}
	return &Cleanup{Proof: proof, Message: message}, nil
}
