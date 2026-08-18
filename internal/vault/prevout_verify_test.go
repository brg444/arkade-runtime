package vault

import (
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func TestRequireVerifiedPrevoutFailClosed(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	spend, err := BuildRoutineSpend(f.routineParams())
	if err != nil {
		t.Fatal(err)
	}
	if prev, err := RequireVerifiedPrevout(spend.Packet); err != nil || prev == nil {
		t.Fatalf("canonical prevout rejected: prev=%v err=%v", prev, err)
	}

	mustReject := func(name string, ptx *psbt.Packet) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s panicked: %v", name, recovered)
			}
		}()
		if _, err := RequireVerifiedPrevout(ptx); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	mustReject("nil packet", nil)
	mustReject("nil unsigned tx", &psbt.Packet{})
	mustReject("empty inputs", &psbt.Packet{UnsignedTx: wire.NewMsgTx(2)})

	clone := func() *psbt.Packet {
		t.Helper()
		raw, err := spend.Packet.B64Encode()
		if err != nil {
			t.Fatal(err)
		}
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		if err != nil {
			t.Fatal(err)
		}
		return ptx
	}

	missingField := clone()
	missingField.Inputs[0].Unknowns = nil
	mustReject("missing prevout field", missingField)

	dup := clone()
	fields, err := txutils.GetArkPsbtFields(dup, 0, arkade.PrevoutTxField)
	if err != nil || len(fields) != 1 {
		t.Fatalf("fixture prevout: %d %v", len(fields), err)
	}
	if err := txutils.SetArkPsbtField(dup, 0, arkade.PrevoutTxField, fields[0]); err != nil {
		t.Fatal(err)
	}
	mustReject("duplicate prevout field", dup)

	hashMismatch := clone()
	hashMismatch.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0] ^= 0x01
	mustReject("hash mismatch", hashMismatch)

	badVout := clone()
	badVout.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 99
	mustReject("vout out of range", badVout)

	noWitness := clone()
	noWitness.Inputs[0].WitnessUtxo = nil
	mustReject("missing witness utxo", noWitness)

	valueMismatch := clone()
	valueMismatch.Inputs[0].WitnessUtxo.Value++
	mustReject("witness value mismatch", valueMismatch)

	scriptMismatch := clone()
	scriptMismatch.Inputs[0].WitnessUtxo.PkScript[0] ^= 0x01
	mustReject("witness script mismatch", scriptMismatch)
}
