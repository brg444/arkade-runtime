package rolling

import (
	"fmt"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/wire"
)

// Proposal is a semantic operation with its complete public construction
// evidence. Admission, finalization and first observation are separate facts.
type Proposal struct {
	Kind            OperationKind
	Message         string
	Transaction     *wire.MsgTx
	Sources         []Source
	Proof, FeeProof HistoryProof
	CreditReceipt   *FinalizationReceipt
	CheckpointExit  []byte
}

// Rebuild independently reconstructs the enrolled program before persistence,
// authorization or receipt issuance. now must come from the service clock.
func (p Proposal) Rebuild(contract *Contract, now int64) (*Transition, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	if len(p.Sources) < 1 || len(p.Sources) > MaxMoneyInputs+1 {
		return nil, fmt.Errorf("operation source count")
	}
	tx := p.Transaction
	if !wellFormedTx(tx) || tx.SerializeSize() > 100000 {
		return nil, fmt.Errorf("malformed operation transaction")
	}
	expectedInputs := len(p.Sources)
	if p.Kind == RenewalOperation {
		expectedInputs++
	}
	if len(tx.TxIn) != expectedInputs {
		return nil, fmt.Errorf("finalized source count")
	}
	var inputValue, outputValue int64
	for _, source := range p.Sources {
		if !wellFormedTx(source.Previous) || source.Previous.SerializeSize() > 100000 || int(source.Index) >= len(source.Previous.TxOut) {
			return nil, fmt.Errorf("invalid finalized source")
		}
		value := source.Previous.TxOut[source.Index].Value
		if value < 0 || value > maxMoney || inputValue > maxMoney-value {
			return nil, fmt.Errorf("invalid finalized input value")
		}
		inputValue += value
	}
	for _, out := range tx.TxOut {
		if out.Value < 0 || out.Value > maxMoney || outputValue > maxMoney-out.Value {
			return nil, fmt.Errorf("invalid finalized output value")
		}
		outputValue += out.Value
	}
	fee := inputValue - outputValue
	var rebuilt *Transition
	switch p.Kind {
	case PaymentOperation:
		if len(tx.TxOut) < 4 {
			return nil, fmt.Errorf("invalid finalized payment")
		}
		rebuilt, err = BuildPayment(c, p.Sources, p.Proof, tx.TxOut[1].PkScript, tx.TxOut[1].Value, fee, p.CheckpointExit)
	case CreditOperation:
		if p.CreditReceipt == nil {
			return nil, fmt.Errorf("missing finalized credit receipt")
		}
		rebuilt, err = BuildCredit(c, p.Sources, *p.CreditReceipt, p.Proof, p.FeeProof, fee, now, p.CheckpointExit)

	case RenewalOperation:
		var message intent.RegisterMessage
		if err = message.Decode(p.Message); err != nil {
			return nil, err
		}
		var renewal *Renewal
		renewal, err = BuildRenewal(c, p.Sources, p.Proof, fee, message.ValidAt, message.ExpireAt)
		if err == nil {
			if renewal.Message != p.Message {
				return nil, fmt.Errorf("noncanonical renewal message")
			}
			rebuilt = &Transition{Transaction: &renewal.Proof.Packet, Before: renewal.Before, After: renewal.After, Debit: renewal.Debit}
		}
	default:
		return nil, fmt.Errorf("unsupported finalized operation")
	}
	if err != nil {
		return nil, err
	}
	if rebuilt.Transaction.UnsignedTx.TxHash() != tx.TxHash() {
		return nil, fmt.Errorf("transaction does not match enrolled operation")
	}
	return rebuilt, nil
}
