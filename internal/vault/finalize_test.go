package vault

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestFinalizeRoutineFailClosed(t *testing.T) {
	t.Parallel()
	f := newSecurityVaultFixture(t)
	ptx := signedRoutine(t, f)

	if err := FinalizeRoutine(nil, f.operational); err == nil {
		t.Fatal("nil packet accepted")
	}
	if err := FinalizeRoutine(ptx, nil); err == nil {
		t.Fatal("nil vault accepted")
	}

	pre := clonePSBT(t, ptx)
	pre.Inputs[0].FinalScriptWitness = []byte{0x01, 0x00}
	if err := FinalizeRoutine(pre, f.operational); err == nil {
		t.Fatal("preexisting final witness accepted")
	}
	preSig := clonePSBT(t, ptx)
	preSig.Inputs[0].FinalScriptSig = []byte{txscript.OP_TRUE}
	if err := FinalizeRoutine(preSig, f.operational); err == nil {
		t.Fatal("preexisting final scriptsig accepted")
	}

	dup := clonePSBT(t, ptx)
	dup.Inputs[0].TaprootScriptSpendSig = append(dup.Inputs[0].TaprootScriptSpendSig, dup.Inputs[0].TaprootScriptSpendSig[0])
	if err := FinalizeRoutine(dup, f.operational); err == nil {
		t.Fatal("duplicate signature accepted")
	}

	for name, missing := range map[string][]byte{
		"PhoneRoutineBIP340": schnorr.SerializePubKey(f.phoneRoutine.PubKey()),
		"VaultCosigner":      schnorr.SerializePubKey(f.operational.TweakedVaultCosigner),
		"ArkadeCosigner":     schnorr.SerializePubKey(f.operational.TweakedArkadeCosigner),
	} {
		t.Run("missing "+name, func(t *testing.T) {
			partial := clonePSBT(t, ptx)
			kept := partial.Inputs[0].TaprootScriptSpendSig[:0]
			for _, sig := range partial.Inputs[0].TaprootScriptSpendSig {
				if !bytes.Equal(sig.XOnlyPubKey, missing) {
					kept = append(kept, sig)
				}
			}
			partial.Inputs[0].TaprootScriptSpendSig = kept
			if err := FinalizeRoutine(partial, f.operational); err == nil {
				t.Fatalf("finalized without the %s signature", name)
			}
		})
	}

	wrongLeaf := clonePSBT(t, ptx)
	wrongLeaf.Inputs[0].TaprootLeafScript[0].Script = append([]byte(nil), f.operational.Leaves.Admin.Script...)
	if err := FinalizeRoutine(wrongLeaf, f.operational); err == nil {
		t.Fatal("wrong leaf accepted")
	}

	wrongHash := clonePSBT(t, ptx)
	wrongHash.Inputs[0].TaprootScriptSpendSig[0].SigHash = txscript.SigHashAll
	if err := FinalizeRoutine(wrongHash, f.operational); err == nil {
		t.Fatal("wrong sighash accepted")
	}

	badSig := clonePSBT(t, ptx)
	badSig.Inputs[0].TaprootScriptSpendSig[0].Signature = make([]byte, 64)
	if err := FinalizeRoutine(badSig, f.operational); err == nil {
		t.Fatal("invalid signature accepted")
	}

	if err := FinalizeRoutine(ptx, f.operational); err != nil {
		t.Fatalf("valid routine finalize: %v", err)
	}
	if err := ExecuteFinalizedRoutine(ptx, f.operational); err != nil {
		t.Fatalf("local engine: %v", err)
	}
}

func signedRoutine(t *testing.T, f *securityVaultFixture) *psbt.Packet {
	t.Helper()
	spend, err := BuildRoutineSpend(f.routineParams())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := webauthn.SignDigestLowS(direct, spend.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{sig}); err != nil {
		t.Fatal(err)
	}
	hotSig, err := SignLeaf(spend.Packet.UnsignedTx, spend.Packet.Inputs[0].WitnessUtxo, f.operational.Leaves.Routine.Script, f.phoneRoutine)
	if err != nil {
		t.Fatal(err)
	}
	AddPartialSig(spend.Packet, f.phoneRoutine.PubKey(), f.operational.Leaves.Routine.Hash, hotSig)
	tweak := arkade.ArkadeScriptHash(f.operational.Record.AuthScript)
	prov := arkade.ComputeArkadeScriptPrivateKey(f.vaultCosigner, tweak)
	provSig, err := SignLeaf(spend.Packet.UnsignedTx, spend.Packet.Inputs[0].WitnessUtxo, f.operational.Leaves.Routine.Script, prov)
	if err != nil {
		t.Fatal(err)
	}
	AddPartialSig(spend.Packet, prov.PubKey(), f.operational.Leaves.Routine.Hash, provSig)
	arkadePriv := arkade.ComputeArkadeScriptPrivateKey(f.arkadeCosigner, tweak)
	arkadeSig, err := SignLeaf(spend.Packet.UnsignedTx, spend.Packet.Inputs[0].WitnessUtxo, f.operational.Leaves.Routine.Script, arkadePriv)
	if err != nil {
		t.Fatal(err)
	}
	AddPartialSig(spend.Packet, arkadePriv.PubKey(), f.operational.Leaves.Routine.Hash, arkadeSig)
	return spend.Packet
}

func clonePSBT(t *testing.T, ptx *psbt.Packet) *psbt.Packet {
	t.Helper()
	raw, err := ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
