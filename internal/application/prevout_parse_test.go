package application

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func TestParseAndVerifyPrevoutFailClosed(t *testing.T) {
	e := newBoundaryEnv(t)
	good := e.canonicalDraft(t, 90_000, 20_000, 500)
	goodB64, err := good.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	if ptx, prev, err := parseAndVerifyPrevout(goodB64); err != nil || ptx == nil || prev == nil {
		t.Fatalf("canonical prevout rejected: ptx=%v prev=%v err=%v", ptx, prev, err)
	}

	mustReject := func(name, raw string) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s panicked: %v", name, recovered)
			}
		}()
		if _, _, err := parseAndVerifyPrevout(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	mustReject("empty", "")
	mustReject("not a psbt", "not-a-psbt")
	mustReject("truncated base64", "cHNid")

	encode := func(mutate func(*psbt.Packet)) string {
		t.Helper()
		ptx := boundaryClonePSBT(t, good)
		mutate(ptx)
		raw, err := ptx.B64Encode()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	mustReject("missing prevout field", encode(func(p *psbt.Packet) {
		p.Inputs[0].Unknowns = nil
	}))
	mustReject("duplicate prevout field", encode(func(p *psbt.Packet) {
		fields, err := txutils.GetArkPsbtFields(p, 0, arkade.PrevoutTxField)
		if err != nil || len(fields) != 1 {
			t.Fatalf("fixture prevout: %d %v", len(fields), err)
		}
		if err := txutils.SetArkPsbtField(p, 0, arkade.PrevoutTxField, fields[0]); err != nil {
			t.Fatal(err)
		}
	}))
	mustReject("hash mismatch", encode(func(p *psbt.Packet) {
		p.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0] ^= 0x01
	}))
	mustReject("vout out of range", encode(func(p *psbt.Packet) {
		p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 99
	}))
	mustReject("missing witness utxo", encode(func(p *psbt.Packet) {
		p.Inputs[0].WitnessUtxo = nil
	}))
	mustReject("witness value mismatch", encode(func(p *psbt.Packet) {
		p.Inputs[0].WitnessUtxo.Value++
	}))
	mustReject("witness script mismatch", encode(func(p *psbt.Packet) {
		p.Inputs[0].WitnessUtxo.PkScript[0] ^= 0x01
	}))
	mustReject("empty inputs", encode(func(p *psbt.Packet) {
		p.Inputs = nil
		p.UnsignedTx.TxIn = nil
	}))
}
