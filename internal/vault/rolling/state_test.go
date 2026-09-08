package rolling

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func TestHistoryRejectsReplayAndDuplicateSequence(t *testing.T) {
	const budget = 10000
	state, err := InitialRollingState(budget)
	if err != nil {
		t.Fatal(err)
	}
	debit := Debit{Amount: 700, Parent: wire.OutPoint{Hash: chainhash.Hash{1}}}
	proof, _, err := BuildHistoryProof(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	charged, err := ApplyDebit(state, budget, debit, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyDebit(charged, budget, debit, proof); err == nil {
		t.Fatal("reused debit sequence")
	}
	removal, _, err := BuildHistoryProof([]Debit{debit}, 0)
	if err != nil {
		t.Fatal(err)
	}
	credited, err := ApplyCredit(charged, budget, debit, removal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyCredit(credited, budget, debit, removal); err == nil {
		t.Fatal("duplicate replenishment")
	}
	if credited.Remaining != budget || credited.Sequence != 1 || credited.Root != state.Root {
		t.Fatal("credit reset sequence or retained debit")
	}
	if _, _, err = BuildHistoryProof([]Debit{debit, debit}, 0); err == nil {
		t.Fatal("duplicate history records")
	}
	// A syntactically valid proof for another leaf cannot restore this debit.
	wrong, _, err := BuildHistoryProof([]Debit{debit}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyCredit(charged, budget, debit, wrong); err == nil {
		t.Fatal("wrong proof accepted")
	}
}

func FuzzRollingStateEncoding(f *testing.F) {
	s, _ := InitialRollingState(10000)
	seed, _ := s.Encode()
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		state, err := DecodeRollingState(raw)
		if err != nil {
			return
		}
		encoded, err := state.Encode()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("accepted noncanonical state")
		}
	})
}

func FuzzDebitEncoding(f *testing.F) {
	d := Debit{Amount: 1000, Parent: wire.OutPoint{Hash: chainhash.Hash{1}}}
	seed, _ := d.Encode()
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		debit, err := DecodeDebit(raw)
		if err != nil {
			return
		}
		encoded, err := debit.Encode()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("accepted noncanonical debit")
		}
	})
}
