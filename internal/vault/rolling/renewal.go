package rolling

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

type Renewal struct {
	Proof         *intent.Proof
	Message       string
	Before, After RollingState
	Debit         *Debit
}

type PrincipalRenewal struct {
	Proof   *intent.Proof
	Message string
}

// CheckRenewalTime bounds new signing authority, separately from historical
// reconstruction. Exact retained responses may be replayed after this window.
func CheckRenewalTime(message string, now int64) error {
	var decoded intent.RegisterMessage
	if err := decoded.Decode(message); err != nil || decoded.ValidAt < 0 || decoded.ExpireAt <= decoded.ValidAt || decoded.ExpireAt-decoded.ValidAt > 3600 || now < decoded.ValidAt || now >= decoded.ExpireAt {
		return fmt.Errorf("rolling renewal authorization window closed")
	}
	return nil
}

// BuildRenewal constructs a controller-bearing registration proof. The service
// must resolve expiry for every source and preserve the resulting batch graph
// before final forfeit signing. Principal-only zero-fee renewal is a separate
// scheduling operation and cannot charge the shared controller.
func BuildRenewal(contract *Contract, sources []Source, proof HistoryProof, fee, validAt, expireAt int64) (*Renewal, error) {
	return buildRenewal(contract, sources, proof, fee, validAt, expireAt, true)
}

// BuildPrincipalRenewal preserves each asset-free principal output exactly,
// without consuming the controller or charging a fee. Source admission and
// renewal windows remain independently verified lifecycle prerequisites.
func BuildPrincipalRenewal(contract *Contract, sources []Source, validAt, expireAt int64) (*PrincipalRenewal, error) {
	for _, source := range sources {
		if !wellFormedTx(source.Previous) {
			return nil, fmt.Errorf("principal renewal source missing")
		}
		ext, err := extension.NewExtensionFromTx(source.Previous)
		if err != nil && !errors.Is(err, extension.ErrExtensionNotFound) {
			return nil, err
		}
		for _, group := range ext.GetAssetPacket() {
			for _, output := range group.Outputs {
				if uint32(output.Vout) == source.Index && output.Amount > 0 {
					return nil, fmt.Errorf("principal renewal cannot consume an asset output")
				}
			}
		}
	}
	built, err := buildRenewal(contract, sources, HistoryProof{}, 0, validAt, expireAt, false)
	if err != nil {
		return nil, err
	}
	return &PrincipalRenewal{Proof: built.Proof, Message: built.Message}, nil
}

func buildRenewal(contract *Contract, sources []Source, proof HistoryProof, fee, validAt, expireAt int64, controller bool) (*Renewal, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	if validAt < 0 || expireAt <= validAt || expireAt-validAt > 3600 {
		return nil, fmt.Errorf("renewal validity bounds")
	}
	inputs, _, err := sourceInputsForRole(c, sources, c.Renew, controller)
	if err != nil {
		return nil, err
	}
	if fee < 0 || fee > c.Parameters.FeeCap || (fee > 0 && (len(inputs) < 2 || !controller)) {
		return nil, fmt.Errorf("renewal fee bounds")
	}
	var before RollingState
	if controller {
		before, err = readState(sources[0].Previous)
		if err != nil {
			return nil, err
		}
	}
	if before.Remaining > c.Parameters.Budget {
		return nil, fmt.Errorf("renewal state exceeds budget")
	}
	message, err := (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, CosignersPublicKeys: []string{hex.EncodeToString(c.Parameters.DelegatePubkey)}, ValidAt: validAt, ExpireAt: expireAt}).Encode()
	if err != nil {
		return nil, err
	}
	selected := make([]intent.Input, 0, len(inputs))
	outputs := make([]*wire.TxOut, 0, len(inputs))
	for _, input := range inputs {
		selected = append(selected, intent.Input{OutPoint: input.Outpoint, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: wire.NewTxOut(input.Amount, bytes.Clone(c.PkScript))})
		outputs = append(outputs, wire.NewTxOut(input.Amount, bytes.Clone(c.PkScript)))
	}
	outputs[len(outputs)-1].Value -= fee
	if outputs[len(outputs)-1].Value < ControllerSats {
		return nil, fmt.Errorf("renewal fee makes dust")
	}
	ptx, err := intent.New(message, selected, outputs)
	if err != nil {
		return nil, err
	}
	after := before
	var debit *Debit
	var witness wire.TxWitness
	if fee > 0 {
		d := Debit{Sequence: before.Sequence, Amount: fee, Parent: ptx.UnsignedTx.TxIn[1].PreviousOutPoint}
		after, err = ApplyDebit(before, c.Parameters.Budget, d, proof)
		if err != nil {
			return nil, err
		}
		debit = &d
		witness = proof.Witness()
	}
	revealed, err := c.Tree.Encode()
	if err != nil {
		return nil, err
	}
	for i := range ptx.Inputs {
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{c.Renew}
		treeField, err := txutils.VtxoTaprootTreeField.Encode(revealed)
		if err != nil {
			return nil, err
		}
		ptx.Inputs[i].Unknowns = append(ptx.Inputs[i].Unknowns, treeField)
		if i > 0 {
			if err := txutils.SetArkPsbtField(&ptx.Packet, i, arkade.PrevArkTxField, *sources[i-1].Previous); err != nil {
				return nil, err
			}
		}
	}
	entries := arkade.EmulatorPacket{}
	for i := 1; i < len(ptx.Inputs); i++ {
		entries = append(entries, arkade.EmulatorEntry{Vin: uint16(i), Script: bytes.Clone(c.Programs.Renew), Witness: witness})
	}
	packets := []extension.Packet{entries}
	if controller {
		id := c.Parameters.ControllerID
		marker := asset.Packet{{AssetId: &id, Inputs: []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 1}}, Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}}}}
		state, err := after.Packet()
		if err != nil {
			return nil, err
		}
		packets = []extension.Packet{marker, entries, state}
	}
	ext, err := extension.NewExtensionFromPackets(packets...)
	if err != nil {
		return nil, err
	}
	raw, err := ext.Serialize()
	if err != nil {
		return nil, err
	}
	ptx.UnsignedTx.AddTxOut(wire.NewTxOut(0, raw))
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
	if fee > int64(ptx.UnsignedTx.SerializeSizeStripped())*c.Parameters.FeerateCap {
		return nil, fmt.Errorf("renewal feerate cap")
	}
	if err := checkWeight(&ptx.Packet); err != nil {
		return nil, err
	}
	return &Renewal{Proof: ptx, Message: message, Before: before, After: after, Debit: debit}, nil
}
