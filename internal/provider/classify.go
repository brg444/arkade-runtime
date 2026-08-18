package provider

import (
	"bytes"
	"fmt"
	"math"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Classified is the structural view of one Operational spend. Caps are
// applied by enforceStaticPolicy, not here.
type Classified struct {
	Recipient *wire.TxOut
	Fee       int64
	VBytes    int64
}

// classifySpend is the shared Draft/Preflight/Bind/Authorize entry: shape
// first, then the static recipient/fee/feerate caps.
func classifySpend(ptx *psbt.Packet, op *vault.Built) (*Classified, error) {
	cl, err := classify(ptx, op)
	if err != nil {
		return nil, err
	}
	if err := enforceStaticPolicy(cl, op.Record.AuthorizationPolicy); err != nil {
		return nil, err
	}
	return cl, nil
}

func enforceStaticPolicy(cl *Classified, policy vault.AuthorizationPolicy) error {
	if cl == nil || cl.Recipient == nil {
		return fmt.Errorf("classified spend required")
	}
	if cl.Recipient.Value > policy.RecipientCapSats {
		return fmt.Errorf("recipient exceeds transaction cap")
	}
	if cl.Fee > policy.AbsoluteFeeCeilingSats {
		return fmt.Errorf("fee exceeds ceiling")
	}
	if cl.VBytes <= 0 {
		return fmt.Errorf("invalid transaction size")
	}
	if cl.Fee > policy.FeerateCeilingSatPerV*cl.VBytes {
		return fmt.Errorf("feerate exceeds ceiling")
	}
	return nil
}

func classify(ptx *psbt.Packet, op *vault.Built) (*Classified, error) {
	if op == nil || op.Leaves.Routine == nil {
		return nil, fmt.Errorf("not enrolled")
	}
	if _, err := vault.RequireVerifiedPrevout(ptx); err != nil {
		return nil, err
	}
	if ptx.UnsignedTx.Version != 2 {
		return nil, fmt.Errorf("transaction version must be 2")
	}
	if ptx.UnsignedTx.LockTime != 0 {
		return nil, fmt.Errorf("locktime must be zero")
	}
	if len(ptx.UnsignedTx.TxIn) != 1 || len(ptx.Inputs) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	if ptx.UnsignedTx.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		return nil, fmt.Errorf("routine sequence must be final")
	}
	if ptx.Inputs[0].SighashType != txscript.SigHashDefault {
		return nil, fmt.Errorf("sighash must be SIGHASH_DEFAULT")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return nil, fmt.Errorf("missing witness utxo")
	}
	if !bytes.Equal(ptx.Inputs[0].WitnessUtxo.PkScript, op.PkScript) {
		return nil, fmt.Errorf("input is not the operational vault")
	}
	if err := requireMoneyRange(ptx.Inputs[0].WitnessUtxo.Value, "input"); err != nil {
		return nil, err
	}
	if len(ptx.Inputs[0].TaprootLeafScript) != 1 || ptx.Inputs[0].TaprootLeafScript[0] == nil {
		return nil, fmt.Errorf("exactly one taproot leaf required")
	}
	leaf := ptx.Inputs[0].TaprootLeafScript[0]
	if !bytes.Equal(leaf.Script, op.Leaves.Routine.Script) {
		return nil, fmt.Errorf("leaf is not the routine path")
	}
	if !bytes.Equal(leaf.ControlBlock, op.Leaves.Routine.ControlBlock) {
		return nil, fmt.Errorf("control block mismatch")
	}
	if leaf.LeafVersion != txscript.BaseLeafVersion {
		return nil, fmt.Errorf("unsupported leaf version")
	}

	var recipient, change, packet *wire.TxOut
	for index, out := range ptx.UnsignedTx.TxOut {
		switch {
		case extension.IsExtension(out.PkScript):
			if packet != nil {
				return nil, fmt.Errorf("multiple extension outputs")
			}
			if out.Value != 0 {
				return nil, fmt.Errorf("extension output must be zero value")
			}
			ext, err := extension.NewExtensionFromBytes(out.PkScript)
			if err != nil {
				return nil, fmt.Errorf("extension: %w", err)
			}
			canonicalExt, err := ext.Serialize()
			if err != nil || !bytes.Equal(canonicalExt, out.PkScript) {
				return nil, fmt.Errorf("non-canonical ark extension encoding")
			}
			if len(ext) != 1 || ext[0].Type() != arkade.PacketType {
				return nil, fmt.Errorf("extension must contain exactly one type 0x01 packet")
			}
			pkt, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
			if err != nil {
				return nil, err
			}
			if len(pkt) != 1 {
				return nil, fmt.Errorf("exactly one emulator entry required")
			}
			unknown, ok := ext[0].(extension.UnknownPacket)
			if !ok {
				return nil, fmt.Errorf("emulator packet")
			}
			rebuiltPkt, err := arkade.NewPacket(pkt[0])
			if err != nil {
				return nil, fmt.Errorf("emulator packet: %w", err)
			}
			canonicalPkt, err := rebuiltPkt.Serialize()
			if err != nil || !bytes.Equal(canonicalPkt, unknown.Data) {
				return nil, fmt.Errorf("non-canonical emulator packet encoding")
			}
			if pkt[0].Vin != 0 {
				return nil, fmt.Errorf("emulator entry vin")
			}
			if !bytes.Equal(pkt[0].Script, op.Record.AuthScript) {
				return nil, fmt.Errorf("authorization script mismatch")
			}
			if index != len(ptx.UnsignedTx.TxOut)-1 {
				return nil, fmt.Errorf("emulator packet output must be last")
			}
			packet = out
		case bytes.Equal(out.PkScript, op.PkScript):
			if change != nil {
				return nil, fmt.Errorf("multiple change outputs")
			}
			if index != 1 || len(ptx.UnsignedTx.TxOut) != 3 {
				return nil, fmt.Errorf("change output must be index one in the three-output form")
			}
			if out.Value < op.Record.AuthorizationPolicy.RecipientDustSats {
				return nil, fmt.Errorf("change below dust")
			}
			change = out
		default:
			if recipient != nil {
				return nil, fmt.Errorf("multiple recipient outputs")
			}
			if !txscript.IsWitnessProgram(out.PkScript) {
				return nil, fmt.Errorf("routine recipient must be a native segwit output")
			}
			if txscript.IsUnspendable(out.PkScript) || isOpReturn(out.PkScript) {
				return nil, fmt.Errorf("unexpected op_return or unspendable output")
			}
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
				return nil, fmt.Errorf("p2a anchor recipient")
			}
			if index != 0 {
				return nil, fmt.Errorf("recipient output must be index zero")
			}
			if out.Value < op.Record.AuthorizationPolicy.RecipientDustSats {
				return nil, fmt.Errorf("recipient below dust")
			}
			recipient = out
		}
	}
	if recipient == nil {
		return nil, fmt.Errorf("missing recipient")
	}
	if packet == nil {
		return nil, fmt.Errorf("missing emulator packet output")
	}
	if change == nil {
		return nil, fmt.Errorf("routine spend requires recursive vault change")
	}

	in := ptx.Inputs[0].WitnessUtxo.Value
	var outSum int64
	for _, o := range ptx.UnsignedTx.TxOut {
		if err := requireMoneyRange(o.Value, "output"); err != nil {
			return nil, err
		}
		next, err := addSats(outSum, o.Value)
		if err != nil {
			return nil, err
		}
		outSum = next
	}
	fee := in - outSum
	if fee < 0 {
		return nil, fmt.Errorf("negative fee")
	}
	vbytes := estimatedVBytes(ptx.UnsignedTx, op)
	if vbytes <= 0 {
		return nil, fmt.Errorf("invalid transaction size")
	}
	return &Classified{
		Recipient: recipient,
		Fee:       fee,
		VBytes:    vbytes,
	}, nil
}

func isOpReturn(pk []byte) bool {
	return len(pk) > 0 && pk[0] == txscript.OP_RETURN
}

func requireMoneyRange(v int64, name string) error {
	if v < 0 || v > btcutil.MaxSatoshi {
		return fmt.Errorf("%s outside bitcoin money range", name)
	}
	return nil
}

func addSats(a, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, fmt.Errorf("output sum overflow")
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, fmt.Errorf("output sum overflow")
	}
	return a + b, nil
}

func estimatedWitnessBytes(op *vault.Built) int {
	if op == nil || op.Leaves.Routine == nil {
		return 0
	}
	return int(vault.RoutineWitnessSize(op.Leaves.Routine.Script, op.Leaves.Routine.ControlBlock))
}

func estimatedFullSize(tx *wire.MsgTx, op *vault.Built) int {
	return tx.SerializeSizeStripped() + estimatedWitnessBytes(op)
}

func estimatedWeight(tx *wire.MsgTx, op *vault.Built) int {
	stripped := tx.SerializeSizeStripped()
	return stripped*3 + estimatedFullSize(tx, op)
}

func estimatedVBytes(tx *wire.MsgTx, op *vault.Built) int64 {
	return int64((estimatedWeight(tx, op) + 3) / 4)
}
