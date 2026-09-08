package rolling

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

type Source struct {
	Previous *wire.MsgTx
	Index    uint32
}

type Transition struct {
	Transaction   *psbt.Packet
	Checkpoints   []*psbt.Packet
	Before, After RollingState
	Debit         *Debit
}

func canonicalContract(c *Contract) (*Contract, error) {
	if c == nil {
		return nil, fmt.Errorf("contract required")
	}
	return BuildContract(c.Parameters, c.Keys, c.Tier, c.ExitDelaySeconds)
}

func readState(tx *wire.MsgTx) (RollingState, error) {
	if tx == nil {
		return RollingState{}, fmt.Errorf("previous transaction required")
	}
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		return RollingState{}, err
	}
	p := ext.GetPacketByType(StatePacketType)
	if p == nil {
		return RollingState{}, fmt.Errorf("controller state missing")
	}
	b, err := p.Serialize()
	if err != nil {
		return RollingState{}, err
	}
	return DecodeRollingState(b)
}

func sourceInputs(c *Contract, sources []Source, leaf *psbt.TaprootTapLeafScript) ([]offchain.VtxoInput, int64, error) {
	if len(sources) < 1 || len(sources) > MaxMoneyInputs+1 || sources[0].Index != 0 {
		return nil, 0, fmt.Errorf("source count or controller index")
	}
	revealed, err := c.Tree.Encode()
	if err != nil {
		return nil, 0, err
	}
	control, err := txscript.ParseControlBlock(leaf.ControlBlock)
	if err != nil {
		return nil, 0, err
	}
	inputs := make([]offchain.VtxoInput, 0, len(sources))
	var principal int64
	seen := make(map[wire.OutPoint]bool)
	for i, source := range sources {
		if !wellFormedTx(source.Previous) || int(source.Index) >= len(source.Previous.TxOut) {
			return nil, 0, fmt.Errorf("missing source")
		}
		for _, in := range source.Previous.TxIn {
			if in == nil {
				return nil, 0, fmt.Errorf("malformed previous transaction")
			}
		}
		for _, out := range source.Previous.TxOut {
			if out == nil {
				return nil, 0, fmt.Errorf("malformed previous transaction")
			}
		}
		out := source.Previous.TxOut[source.Index]
		if out.Value < ControllerSats || out.Value > maxMoney || !bytes.Equal(out.PkScript, c.PkScript) {
			return nil, 0, fmt.Errorf("source value or contract")
		}
		if i == 0 && out.Value != ControllerSats {
			return nil, 0, fmt.Errorf("controller value")
		}
		op := wire.OutPoint{Hash: source.Previous.TxHash(), Index: source.Index}
		if seen[op] {
			return nil, 0, fmt.Errorf("duplicate source")
		}
		seen[op] = true
		inputs = append(inputs, offchain.VtxoInput{Outpoint: &op, Amount: out.Value, Tapscript: &waddrmgr.Tapscript{ControlBlock: control, RevealedScript: leaf.Script}, RevealedTapscripts: revealed})
		if i > 0 {
			if principal > maxMoney-out.Value {
				return nil, 0, fmt.Errorf("principal overflow")
			}
			principal += out.Value
		}
	}
	return inputs, principal, nil
}

func nativeTransaction(c *Contract, sources []Source, inputs []offchain.VtxoInput, outputs []*wire.TxOut, fee int64, checkpointExit []byte) (*psbt.Packet, []*psbt.Packet, error) {
	if fee < 0 || fee > c.Parameters.FeeCap {
		return nil, nil, fmt.Errorf("fee exceeds cap")
	}
	if !bytes.Equal(checkpointExit, c.Parameters.CheckpointExit) {
		return nil, nil, fmt.Errorf("checkpoint exit differs from enrollment pin")
	}

	// The qualified stock Operator reconstructs transactions with input/output
	// equality. A nonzero native fee is currently inadmissible; renewal fees
	// remain supported through the intent path.
	if fee != 0 {
		return nil, nil, fmt.Errorf("qualified Operator requires zero native transaction fee")
	}
	p, cps, err := offchain.BuildTxs(inputs, outputs, checkpointExit)
	if err != nil {
		return nil, nil, err
	}

	for i, source := range sources {
		if err := txutils.SetArkPsbtField(p, i, arkade.PrevArkTxField, *source.Previous); err != nil {
			return nil, nil, err
		}
	}
	return p, cps, nil
}

func completeTransition(c *Contract, p *psbt.Packet, cps []*psbt.Packet, before, after RollingState, debit *Debit, code []byte, witness wire.TxWitness, fee int64) (*Transition, error) {
	entries := arkade.EmulatorPacket{}
	for i := range p.Inputs {
		entries = append(entries, arkade.EmulatorEntry{Vin: uint16(i), Script: bytes.Clone(code), Witness: witness})
	}
	id := c.Parameters.ControllerID
	marker := asset.Packet{{AssetId: &id, Inputs: []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 1}}, Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}}}}
	state, err := after.Packet()
	if err != nil {
		return nil, err
	}
	ext, err := extension.NewExtensionFromPackets(marker, entries, state)
	if err != nil {
		return nil, err
	}
	raw, err := ext.Serialize()
	if err != nil {
		return nil, err
	}
	anchor := len(p.UnsignedTx.TxOut) - 1
	p.UnsignedTx.TxOut = append(p.UnsignedTx.TxOut[:anchor], wire.NewTxOut(0, raw), p.UnsignedTx.TxOut[anchor])
	p.Outputs = append(p.Outputs, psbt.POutput{})
	if fee > int64(p.UnsignedTx.SerializeSizeStripped())*c.Parameters.FeerateCap {
		return nil, fmt.Errorf("fee exceeds stripped-size feerate cap")
	}
	if err := checkWeight(p); err != nil {
		return nil, err
	}
	return &Transition{Transaction: p, Checkpoints: cps, Before: before, After: after, Debit: debit}, nil
}

// BuildPayment constructs an unsigned native checkpoint spend. Callers must
// authenticate source admission and assets, persist the exact proposal before
// signatures, and reconcile its outcome before advancing controller authority.
func BuildPayment(contract *Contract, sources []Source, proof HistoryProof, recipient []byte, amount, fee int64, checkpointExit []byte) (*Transition, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	if amount < ControllerSats || amount > c.Parameters.RecipientCap || !txscript.IsPayToTaproot(recipient) || fee < 0 || fee > c.Parameters.FeeCap {
		return nil, fmt.Errorf("payment amount, fee or destination")
	}
	inputs, principal, err := sourceInputs(c, sources, c.Spend)
	if err != nil {
		return nil, err
	}
	if len(inputs) < 2 || amount+fee > principal {
		return nil, fmt.Errorf("insufficient principal")
	}
	before, err := readState(sources[0].Previous)
	if err != nil {
		return nil, err
	}
	outputs := []*wire.TxOut{wire.NewTxOut(ControllerSats, c.PkScript), wire.NewTxOut(amount, recipient)}
	if change := principal - amount - fee; change > 0 {
		if change < ControllerSats {
			return nil, fmt.Errorf("dust change")
		}
		outputs = append(outputs, wire.NewTxOut(change, c.PkScript))
	}
	p, cps, err := nativeTransaction(c, sources, inputs, outputs, fee, checkpointExit)
	if err != nil {
		return nil, err
	}
	d := Debit{Sequence: before.Sequence, Amount: amount + fee, Parent: p.UnsignedTx.TxIn[0].PreviousOutPoint}
	after, err := ApplyDebit(before, c.Parameters.Budget, d, proof)
	if err != nil {
		return nil, err
	}
	return completeTransition(c, p, cps, before, after, &d, c.Programs.Spend, proof.Witness(), fee)
}

// BuildCredit removes a mature debit. A positive fee inserts a new obligation,
// proven against the root after removal using feeProof. No history is trusted
// unless both proofs reconcile with the selected controller's committed root.
func BuildCredit(contract *Contract, sources []Source, receipt FinalizationReceipt, removal, feeProof HistoryProof, fee, now int64, checkpointExit []byte) (*Transition, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	if err := receipt.Verify(c.Parameters, now); err != nil {
		return nil, err
	}
	inputs, principal, err := sourceInputs(c, sources, c.Credit)
	if err != nil {
		return nil, err
	}
	if fee < 0 || fee > c.Parameters.FeeCap || fee > principal {
		return nil, fmt.Errorf("credit fee bounds")
	}
	before, err := readState(sources[0].Previous)
	if err != nil {
		return nil, err
	}
	after, err := ApplyCredit(before, c.Parameters.Budget, receipt.Debit, removal)
	if err != nil {
		return nil, err
	}
	outputs := []*wire.TxOut{wire.NewTxOut(ControllerSats, c.PkScript)}
	if len(inputs) > 1 {
		if principal-fee < ControllerSats {
			return nil, fmt.Errorf("credit change dust")
		}
		outputs = append(outputs, wire.NewTxOut(principal-fee, c.PkScript))
	}
	p, cps, err := nativeTransaction(c, sources, inputs, outputs, fee, checkpointExit)
	if err != nil {
		return nil, err
	}
	witness := removal.Witness()
	var debit *Debit
	if fee > 0 {
		d := Debit{Sequence: before.Sequence, Amount: fee, Parent: p.UnsignedTx.TxIn[0].PreviousOutPoint}
		after, err = ApplyDebit(after, c.Parameters.Budget, d, feeProof)
		if err != nil {
			return nil, err
		}
		debit = &d
		witness = append(feeProof.Witness(), witness...)
	}
	message, err := receipt.Message()
	if err != nil {
		return nil, err
	}
	witness = append(witness, bytes.Clone(receipt.Signature[:]), message)
	return completeTransition(c, p, cps, before, after, debit, c.Programs.Credit, witness, fee)
}
