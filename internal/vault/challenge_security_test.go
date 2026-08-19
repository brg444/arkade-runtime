package vault

import (
	"bytes"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func TestArkadeChallengeMasksOnlyPacketWitness(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	spend, err := BuildRoutineSpend(f.routineParams())
	if err != nil {
		t.Fatal(err)
	}
	beforeChallenge := append([]byte(nil), spend.Challenge...)
	beforeTxID := spend.Packet.UnsignedTx.TxHash()

	witness := wire.TxWitness{bytes.Repeat([]byte{0x11}, 64)}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, witness); err != nil {
		t.Fatalf("SetPacketWitness: %v", err)
	}
	afterChallenge, err := Challenge(spend.Packet, f.operational)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeChallenge, afterChallenge) {
		t.Fatalf("packet witness changed Arkade challenge: before=%x after=%x", beforeChallenge, afterChallenge)
	}
	if spend.Packet.UnsignedTx.TxHash() == beforeTxID {
		t.Fatal("packet witness did not change the Bitcoin transaction id; test is not exercising output masking")
	}
	packet, err := arkade.FindEmulatorPacket(spend.Packet.UnsignedTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 1 || !securityWitnessEqual(packet[0].Witness, witness) {
		t.Fatal("updated packet did not preserve the exact packet witness")
	}
}

func TestArkadeChallengeCommitsToEveryTransactionMutation(t *testing.T) {
	f := newSecurityVaultFixture(t)
	baseline, err := BuildRoutineSpend(f.routineParams())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*SpendParams)
	}{
		{name: "destination", mutate: func(p *SpendParams) {
			p.RecipientScript = append([]byte(nil), p.RecipientScript...)
			p.RecipientScript[len(p.RecipientScript)-1] ^= 1
		}},
		{name: "recipient amount", mutate: func(p *SpendParams) { p.RecipientAmount++ }},
		{name: "fee and change", mutate: func(p *SpendParams) { p.Fee++ }},
		{name: "prevout", mutate: func(p *SpendParams) {
			p.PrevTx = cloneSecurityTx(p.PrevTx)
			p.PrevTx.TxOut[0].Value++
			p.PrevOutPoint.Hash = p.PrevTx.TxHash()
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := f.routineParams()
			tc.mutate(&params)
			mutated, err := BuildRoutineSpend(params)
			if err != nil {
				t.Fatalf("build mutated spend: %v", err)
			}
			if bytes.Equal(mutated.Challenge, baseline.Challenge) {
				t.Fatalf("%s mutation did not change Arkade challenge %x", tc.name, baseline.Challenge)
			}
		})
	}

	// Sequence is pinned to 0xffffffff by the builder. Mutate the assembled
	// transaction to prove the challenge still commits to that field.
	seq := clonePSBT(t, baseline.Packet)
	seq.UnsignedTx.TxIn[0].Sequence = 1
	seqChallenge, err := Challenge(seq, f.operational)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(seqChallenge, baseline.Challenge) {
		t.Fatal("sequence mutation did not change Arkade challenge")
	}
}

func TestCollaborativeBuilderCommitsCanonicalPrevoutAndPacket(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	spend, err := BuildRoutineSpend(f.routineParams())
	if err != nil {
		t.Fatal(err)
	}
	fields, err := txutils.GetArkPsbtFields(spend.Packet, 0, arkade.PrevoutTxField)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[0].TxHash() != f.prevTx.TxHash() {
		t.Fatal("PSBT does not contain exactly the transaction that authenticates its prevout")
	}
	packet, err := arkade.FindEmulatorPacket(spend.Packet.UnsignedTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 1 || packet[0].Vin != 0 {
		t.Fatalf("emulator packet = %#v, want one entry for vin 0", packet)
	}
	if !bytes.Equal(packet[0].Script, f.operational.Record.AuthScript) {
		t.Fatal("emulator packet does not commit to the vault's authorization script")
	}
	if len(packet[0].Witness) != 0 {
		t.Fatal("preflight builder must start with an empty packet witness")
	}
}

func TestCollaborativeBuilderRejectsPrevTxThatDoesNotAuthenticateOutpoint(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	params := f.routineParams()
	params.PrevOutPoint.Hash = chainhash.Hash{1}
	if _, err := BuildRoutineSpend(params); err == nil {
		t.Fatal("builder accepted PrevTx whose txid does not match PrevOutPoint.Hash")
	}
}

func securityWitnessEqual(a, b wire.TxWitness) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
