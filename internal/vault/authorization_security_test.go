package vault

import (
	"bytes"
	"crypto/elliptic"
	"math"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestAuthorizationScriptEnforcesTransactionPolicyForBothCosigners(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	spend, err := BuildRoutineSpend(f.routineParams())
	if err != nil {
		t.Fatal(err)
	}
	bindDirect := func(ptx *psbt.Packet) {
		t.Helper()
		challenge, err := Challenge(ptx, f.operational)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetPacketWitness(ptx.UnsignedTx, wire.TxWitness{signDirectP256LowS(t, f.phoneDirect, challenge)}); err != nil {
			t.Fatal(err)
		}
	}
	bindDirect(spend.Packet)
	cosigners := map[string]*btcec.PublicKey{
		"private vault cosigner":  f.vaultCosigner.PubKey(),
		"ArkadeCosigner cosigner": f.arkadeCosigner.PubKey(),
	}
	policy := f.operational.Record.AuthorizationPolicy
	for name, base := range cosigners {
		if err := executeRawPacketAuthorization(spend.Packet, base); err != nil {
			t.Fatalf("%s rejected the shared valid policy script: %v", name, err)
		}
	}

	// A routine full drain is rejected by both the builder and the raw policy.
	noChangePrev := f.prevTx.Copy()
	noChangePrev.TxOut[0].Value = securityRecipientSats + securityFeeSats
	noChangeParams := f.routineParams()
	noChangeParams.PrevTx = noChangePrev
	noChangeParams.PrevOutPoint.Hash = noChangePrev.TxHash()
	if _, err := BuildRoutineSpend(noChangeParams); err == nil {
		t.Fatal("routine builder accepted a no-change full drain")
	}
	noChange := clonePSBT(t, spend.Packet)
	noChange.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = noChangePrev.TxHash()
	noChange.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    noChangePrev.TxOut[0].Value,
		PkScript: append([]byte(nil), noChangePrev.TxOut[0].PkScript...),
	}
	noChange.UnsignedTx.TxOut = []*wire.TxOut{
		{Value: securityRecipientSats, PkScript: append([]byte(nil), spend.Packet.UnsignedTx.TxOut[0].PkScript...)},
		spend.Packet.UnsignedTx.TxOut[2],
	}
	if err := txutils.SetArkPsbtField(noChange, 0, arkade.PrevoutTxField, *noChangePrev); err != nil {
		t.Fatal(err)
	}
	bindDirect(noChange)
	for name, base := range cosigners {
		if err := executeRawPacketAuthorization(noChange, base); err == nil {
			t.Fatalf("%s accepted a raw no-change full drain", name)
		}
	}

	// Put the real ARK extension at positive-value recipient index zero and an
	// unrelated zero OP_RETURN last. Both raw signers must reject the moved
	// packet itself, independently of the ordinary change-script check.
	movedPacket := clonePSBT(t, spend.Packet)
	recipientValue := movedPacket.UnsignedTx.TxOut[0].Value
	extensionScript := append([]byte(nil), movedPacket.UnsignedTx.TxOut[2].PkScript...)
	movedPacket.UnsignedTx.TxOut[0] = &wire.TxOut{Value: recipientValue, PkScript: extensionScript}
	movedPacket.UnsignedTx.TxOut[2] = &wire.TxOut{Value: 0, PkScript: []byte{txscript.OP_RETURN, 0x01, 0x00}}
	bindDirect(movedPacket)
	for name, base := range cosigners {
		if err := executeRawPacketAuthorization(movedPacket, base); err == nil {
			t.Fatalf("%s accepted an extension moved to recipient index zero", name)
		}
	}

	// Bind the exact raw-VM feerate edge, independently of Go classification.
	stripped := spend.Packet.UnsignedTx.SerializeSizeStripped()
	vbytes := int64((stripped*4 + int(RoutineWitnessBytes) + 3) / 4)
	feeLimit := policy.FeerateCeilingSatPerV * vbytes
	if feeLimit > policy.AbsoluteFeeCeilingSats {
		t.Fatalf("fixture feerate boundary %d exceeds absolute cap %d", feeLimit, policy.AbsoluteFeeCeilingSats)
	}
	for name, fee := range map[string]int64{
		"at exact feerate cap":     feeLimit,
		"one sat over feerate cap": feeLimit + 1,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePSBT(t, spend.Packet)
			candidate.UnsignedTx.TxOut[1].Value = securityPrevoutValue - candidate.UnsignedTx.TxOut[0].Value - fee
			bindDirect(candidate)
			for role, base := range cosigners {
				err := executeRawPacketAuthorization(candidate, base)
				if fee == feeLimit && err != nil {
					t.Fatalf("%s rejected exact raw feerate cap: %v", role, err)
				}
				if fee > feeLimit && err == nil {
					t.Fatalf("%s accepted raw feerate cap plus one sat", role)
				}
			}
		})
	}

	mutations := []struct {
		name   string
		mutate func(*psbt.Packet)
	}{
		{name: "wrong version", mutate: func(p *psbt.Packet) { p.UnsignedTx.Version = 3 }},
		{name: "nonzero locktime", mutate: func(p *psbt.Packet) { p.UnsignedTx.LockTime = 1 }},
		{name: "nonfinal sequence", mutate: func(p *psbt.Packet) { p.UnsignedTx.TxIn[0].Sequence = math.MaxUint32 - 1 }},
		{name: "recipient below dust", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[0].Value = policy.RecipientDustSats - 1
			p.UnsignedTx.TxOut[1].Value = securityPrevoutValue - p.UnsignedTx.TxOut[0].Value - securityFeeSats
		}},
		{name: "recipient above cap", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[0].Value = policy.RecipientCapSats + 1
			p.UnsignedTx.TxOut[1].Value = securityPrevoutValue - p.UnsignedTx.TxOut[0].Value - securityFeeSats
		}},
		{name: "change leaves vault", mutate: func(p *psbt.Packet) { p.UnsignedTx.TxOut[1].PkScript = []byte{txscript.OP_TRUE} }},
		{name: "change below dust", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[1].Value = policy.RecipientDustSats - 1
		}},
		{name: "packet not last", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[1], p.UnsignedTx.TxOut[2] = p.UnsignedTx.TxOut[2], p.UnsignedTx.TxOut[1]
		}},
		{name: "packet has value", mutate: func(p *psbt.Packet) { p.UnsignedTx.TxOut[2].Value = 1 }},
		{name: "negative fee", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[1].Value = securityPrevoutValue - p.UnsignedTx.TxOut[0].Value + 1
		}},
		{name: "absolute fee above cap", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[1].Value = securityPrevoutValue - p.UnsignedTx.TxOut[0].Value - policy.AbsoluteFeeCeilingSats - 1
		}},
		{name: "extra output", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePSBT(t, spend.Packet)
			test.mutate(candidate)
			bindDirect(candidate)
			for name, base := range cosigners {
				if err := executeRawPacketAuthorization(candidate, base); err == nil {
					t.Fatalf("%s accepted policy violation", name)
				}
			}
		})
	}
}

func TestAuthorizationScriptEndsWithExactDirectP256Program(t *testing.T) {
	t.Parallel()

	priv, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	compressed := webauthn.CompressedP256(priv)
	got, err := AuthorizationScript(compressed, fixtureAuthorizationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	extendedKey := append([]byte{0x11}, compressed...)
	want, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddOp(arkade.OP_SIGHASH).
		AddData(extendedKey).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		Script()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, want) {
		t.Fatalf("authorization script does not end in exact DirectP256 program: got %x, suffix %x", got, want)
	}
}

// WebAuthn assertion fields are provider-side ceremony evidence, not the
// Arkade witness. The direct-signer program must reject the legacy three-item
// witness instead of putting clientDataJSON/authenticatorData on-chain.
func TestAuthorizationScriptRejectsLegacyWebAuthnWireWitness(t *testing.T) {
	t.Parallel()

	directKey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	webauthnKey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}

	f := newSecurityVaultFixture(t)
	op, err := NewOperational(OperationalKeys{
		PhoneRoutineBIP340:  f.phoneRoutine.PubKey(),
		ExternalOwnerWallet: f.externalOwner.PubKey(),
		VaultCosignerBase:   f.vaultCosigner.PubKey(),
		ArkadeCosignerBase:  f.arkadeCosigner.PubKey(),
		PhoneDirectP256:     webauthn.CompressedP256(directKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	prevTx := f.prevTx.Copy()
	prevTx.TxOut[0].PkScript = append([]byte(nil), op.PkScript...)
	params := f.routineParams()
	params.Vault = op
	params.PrevTx = prevTx
	params.PrevOutPoint.Hash = prevTx.TxHash()
	spend, err := BuildRoutineSpend(params)
	if err != nil {
		t.Fatal(err)
	}

	directSig := signDirectP256LowS(t, directKey, spend.Challenge)
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, f.vaultCosigner.PubKey()); err != nil {
		t.Fatalf("test setup failed: one-item direct signature was rejected: %v", err)
	}

	assertion, err := webauthn.Synth(
		webauthnKey, []byte("credential"), spend.Challenge,
		"http://localhost:8787", "localhost", true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := webauthn.CompactLowS(assertion.DERSignature)
	if err != nil {
		t.Fatal(err)
	}
	witness := wire.TxWitness{compact, assertion.AuthenticatorData, assertion.ClientDataJSON}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, witness); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, f.vaultCosigner.PubKey()); err == nil {
		t.Fatal("direct authorization script accepted legacy WebAuthn assertion witness")
	}
}

func TestAuthorizationScriptRejectsWrongP256KeyLength(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 32, 34} {
		if _, err := AuthorizationScript(make([]byte, size), fixtureAuthorizationPolicy()); err == nil {
			t.Fatalf("AuthorizationScript accepted %d-byte P-256 key", size)
		}
	}
}

func TestAuthorizationScriptRejectsOffCurveAndNoncanonicalP256(t *testing.T) {
	t.Parallel()

	priv, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	valid := webauthn.CompressedP256(priv)
	if _, err := AuthorizationScript(valid, fixtureAuthorizationPolicy()); err != nil {
		t.Fatalf("valid compressed PhoneDirectP256: %v", err)
	}

	offCurve := make([]byte, 33)
	offCurve[0] = 0x02
	elliptic.P256().Params().P.FillBytes(offCurve[1:])

	wrongPrefix := append([]byte{0x04}, valid[1:]...)
	hybrid := append([]byte{0x06}, valid[1:]...)

	for name, key := range map[string][]byte{
		"off-curve x=p":       offCurve,
		"uncompressed prefix": wrongPrefix,
		"hybrid prefix":       hybrid,
	} {
		if _, err := AuthorizationScript(key, fixtureAuthorizationPolicy()); err == nil {
			t.Fatalf("AuthorizationScript accepted %s key %x", name, key)
		}
	}
}
