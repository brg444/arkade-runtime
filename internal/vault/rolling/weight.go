package rolling

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// MaxTransactionWeight matches the qualified stock Operator admission limit.
const MaxTransactionWeight = 40000

// SignedWeight reconstructs the complete witness size, including all required
// signatures. It accepts only this profile's canonical multisig input leaves.
func SignedWeight(p *psbt.Packet) (int, error) {
	if p == nil || !wellFormedTx(p.UnsignedTx) || len(p.Inputs) != len(p.UnsignedTx.TxIn) {
		return 0, fmt.Errorf("malformed weight input")
	}
	tx := p.UnsignedTx.Copy()
	for i, input := range p.Inputs {
		if len(input.TaprootLeafScript) != 1 || input.TaprootLeafScript[0] == nil {
			return 0, fmt.Errorf("selected leaf required")
		}
		leaf := input.TaprootLeafScript[0]
		closure := &script.MultisigClosure{}
		ok, err := closure.Decode(leaf.Script)
		if err != nil || !ok {
			return 0, fmt.Errorf("weight requires multisig leaf")
		}
		size := 64
		if input.SighashType != txscript.SigHashDefault {
			size++
		}
		w := make(wire.TxWitness, 0, len(closure.PubKeys)+2)
		for range closure.PubKeys {
			w = append(w, make([]byte, size))
		}
		w = append(w, leaf.Script, leaf.ControlBlock)
		tx.TxIn[i].Witness = w
	}
	return tx.SerializeSizeStripped()*3 + tx.SerializeSize(), nil
}

func checkWeight(p *psbt.Packet) error {
	weight, err := SignedWeight(p)
	if err != nil {
		return err
	}
	if weight > MaxTransactionWeight {
		return fmt.Errorf("signed transaction weight %d exceeds %d; select fewer inputs", weight, MaxTransactionWeight)
	}
	return nil
}
