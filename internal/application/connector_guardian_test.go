package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// All keys in this test are disposable. The candidate is built through the
// isolated connector constructors; this package only signs its Savings input
// in the scoped Guardian role.
type connectorGuardianFixture struct {
	phone, hardware, guardian, emulator *btcec.PrivateKey
	guardianProg                        *btcec.PrivateKey
	family                              *connector.Family
	destination                         []byte
	stored                              string
	auth                                connectorGuardianAuthorization
}

func connectorKey(n byte) *btcec.PrivateKey {
	k, _ := btcec.PrivKeyFromBytes([]byte{n})
	return k
}

func newConnectorGuardianFixtureFor(t *testing.T, vaultID string, phone, hardware, guardian, emulator *btcec.PrivateKey) *connectorGuardianFixture {
	t.Helper()
	f := &connectorGuardianFixture{phone: phone, hardware: hardware, guardian: guardian, emulator: emulator}
	direct, err := hex.DecodeString("02c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := program.DefaultSpendingPolicyFor("mutinynet")
	if err != nil {
		t.Fatal(err)
	}
	fam, err := connector.BuildFamily(savings.FamilyInput{
		VaultID: vaultID, Network: "mutinynet",
		Phone: f.phone.PubKey(), Hardware: f.hardware.PubKey(),
		PhoneDirectP256:   direct,
		VaultCosignerBase: f.guardian.PubKey(), ArkadeCosignerBase: f.emulator.PubKey(),
		ProtectionTier: program.ProtectionTierStandard, SpendingPolicy: policy,
		ServerFreeClawback: true,
	}, connector.Taproot)
	if err != nil {
		t.Fatal(err)
	}
	f.family = fam
	dest, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(connectorKey(17).PubKey()))
	if err != nil {
		t.Fatal(err)
	}
	f.destination = dest
	savingsParent := wire.NewMsgTx(2)
	savingsParent.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 99}, nil, nil))
	savingsParent.AddTxOut(wire.NewTxOut(10000, fam.Recovery.Savings.PkScript))
	connectorParent := wire.NewMsgTx(2)
	connectorParent.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 99}, nil, nil))
	connectorParent.AddTxOut(wire.NewTxOut(connector.ReserveSats, fam.Rules.ConnectorScript))
	savingsOP := wire.OutPoint{Hash: savingsParent.TxHash(), Index: 0}
	connectorOP := wire.OutPoint{Hash: connectorParent.TxHash(), Index: 0}
	draft, err := connector.Prepare(connector.Request{
		Rules: fam.Rules,
		Parents: connector.Parents{
			savingsOP: savingsParent, connectorOP: connectorParent,
		},
		Savings: savingsOP, Connector: connectorOP,
		SavingsScript: fam.Recovery.Savings.PkScript, Leaf: fam.Leaf, Control: fam.Control,
		DestinationScript: dest,
		Phone:             f.phone.PubKey(), GuardianBase: f.guardian.PubKey(), EmulatorBase: f.emulator.PubKey(),
		Origin: connector.KeyOrigin{Type: connector.Taproot, PublicKey: f.hardware.PubKey().SerializeCompressed(),
			Fingerprint: 0x12345678, Path: []uint32{0x80000056, 0x80000001, 0x80000000, 0, 0}},
		AmountSats: 8000, FeeSats: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := draft.PSBT()
	if err != nil {
		t.Fatal(err)
	}
	signConnectorInputWithPhone(t, packet, f.phone, fam.Leaf)
	f.stored, err = packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.guardianProg = arkade.ComputeArkadeScriptPrivateKey(f.guardian, arkade.ArkadeScriptHash(fam.Program))
	if f.guardianProg == nil {
		t.Fatal("guardian program tweak is degenerate")
	}
	f.auth, err = newConnectorGuardianAuthorization(
		f.phone.PubKey(), f.guardian.PubKey(), f.emulator.PubKey(),
		fam.Control, fam.Rules.ConnectorScript, fam.Rules,
	)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newConnectorGuardianFixture(t *testing.T) *connectorGuardianFixture {
	t.Helper()
	return newConnectorGuardianFixtureFor(t, "connector-guardian-test",
		connectorKey(3), connectorKey(4), connectorKey(14), connectorKey(15))
}

// signConnectorInputWithPhone (re)signs input 0 with the phone key over the
// packet's current leaf script. Proof-metadata tampering leaves this signature
// valid, so tests can attribute rejection to the proof check itself.
func signConnectorInputWithPhone(t *testing.T, packet *psbt.Packet, phone *btcec.PrivateKey, leafScript []byte) {
	t.Helper()
	savingsOut := packet.Inputs[connector.SavingsInput].WitnessUtxo
	leaf := txscript.NewBaseTapLeaf(leafScript)
	sig, err := txscript.RawTxInTapscriptSignature(
		packet.UnsignedTx, txscript.NewTxSigHashes(packet.UnsignedTx, multiWitnessFetcher(packet)),
		connector.SavingsInput, savingsOut.Value, savingsOut.PkScript, leaf, txscript.SigHashDefault, phone,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 65 {
		sig = sig[:64]
	}
	leafHash := leaf.TapHash()
	packet.Inputs[connector.SavingsInput].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		Signature: sig, XOnlyPubKey: schnorr.SerializePubKey(phone.PubKey()),
		LeafHash: leafHash[:], SigHash: txscript.SigHashDefault,
	}}
}

func decodeConnectorStage(t *testing.T, encoded string) *psbt.Packet {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
	if err != nil {
		t.Fatal(err)
	}
	return ptx
}

func encodeConnectorStage(t *testing.T, packet *psbt.Packet) string {
	t.Helper()
	raw, err := packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignConnectorGuardianStage(t *testing.T) {
	f := newConnectorGuardianFixture(t)
	signed, err := signConnectorGuardianStage(context.Background(), f.stored, f.guardianProg, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	before := decodeConnectorStage(t, f.stored)
	after := decodeConnectorStage(t, signed)
	var want, got bytes.Buffer
	if err := before.UnsignedTx.Serialize(&want); err != nil {
		t.Fatal(err)
	}
	if err := after.UnsignedTx.Serialize(&got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Fatal("guardian signing changed the candidate transaction")
	}
	beforeSigs := before.Inputs[connector.SavingsInput].TaprootScriptSpendSig
	afterSigs := after.Inputs[connector.SavingsInput].TaprootScriptSpendSig
	if len(beforeSigs) != 1 || len(afterSigs) != 2 {
		t.Fatalf("expected exactly one new guardian signature, got %d -> %d", len(beforeSigs), len(afterSigs))
	}
	if !bytes.Equal(afterSigs[0].Signature, beforeSigs[0].Signature) {
		t.Fatal("phone signature was not preserved")
	}
	if err := verifySchnorrOnInputWithSighash(
		after, connector.SavingsInput, afterSigs[1].Signature,
		schnorr.SerializePubKey(f.guardianProg.PubKey()), f.family.Leaf, txscript.SigHashDefault,
	); err != nil {
		t.Fatalf("guardian signature invalid: %v", err)
	}
	if len(after.Inputs[connector.ConnectorInput].TaprootScriptSpendSig) != 0 ||
		len(after.Inputs[connector.ConnectorInput].PartialSigs) != 0 {
		t.Fatal("guardian helper must never touch the connector input")
	}
	// A second call must fail: the Guardian signature is already present.
	if _, err := signConnectorGuardianStage(context.Background(), signed, f.guardianProg, f.auth); err == nil {
		t.Fatal("accepted duplicate guardian signature")
	}
}

func TestSignConnectorGuardianStageRejects(t *testing.T) {
	t.Run("one_input_not_signed", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		tiny := wire.NewMsgTx(2)
		tiny.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, nil, nil))
		packet, err := psbt.NewFromUnsignedTx(tiny)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("signed a non-connector single-input PSBT")
		}
	})
	t.Run("missing_phone_signature", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		packet.Inputs[connector.SavingsInput].TaprootScriptSpendSig = nil
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("signed without the phone signature")
		}
	})
	t.Run("wrong_phone_identity", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		// A different enrolled phone derives a different normal leaf, so the
		// candidate leaf no longer commits the authorized identities.
		auth, err := newConnectorGuardianAuthorization(
			connectorKey(40).PubKey(), f.guardian.PubKey(), f.emulator.PubKey(),
			f.family.Control, f.family.Rules.ConnectorScript, f.family.Rules,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signConnectorGuardianStage(context.Background(), f.stored, f.guardianProg, auth); err == nil {
			t.Fatal("accepted a phone identity that never signed")
		}
	})
	t.Run("substituted_connector_script", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		attacker, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(connectorKey(16).PubKey()))
		if err != nil {
			t.Fatal(err)
		}
		packet.Inputs[connector.ConnectorInput].WitnessUtxo.PkScript = attacker
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("signed with an attacker connector input")
		}
	})
	t.Run("mutated_recipient_after_phone_sig", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		packet.UnsignedTx.TxOut[connector.DestinationOutput].Value++
		// The phone signature no longer binds this transaction; the helper
		// must reject the substitution instead of countersigning it.
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("countersigned a substituted transaction")
		}
	})
	t.Run("foreign_leaf_with_valid_phone_sig", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		// Swap the leaf and re-sign with the phone so the signature is fresh
		// and valid; rejection must come from the leaf-identity check.
		foreign, err := savings.Checksig(f.phone.PubKey(), f.emulator.PubKey())
		if err != nil {
			t.Fatal(err)
		}
		packet.Inputs[connector.SavingsInput].TaprootLeafScript[0].Script = foreign
		signConnectorInputWithPhone(t, packet, f.phone, foreign)
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("signed under a foreign leaf")
		}
	})
	t.Run("weak_sighash", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		packet.Inputs[connector.SavingsInput].SighashType = txscript.SigHashAll
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("signed a weak-sighash savings input")
		}
	})
	t.Run("tampered_fee_rules_are_not_an_oracle", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		rules := f.family.Rules
		rules.AbsoluteFeeCapSats++
		auth, err := newConnectorGuardianAuthorization(
			f.phone.PubKey(), f.guardian.PubKey(), f.emulator.PubKey(),
			f.family.Control, f.family.Rules.ConnectorScript, rules,
		)
		if err != nil {
			t.Fatal(err)
		}
		// The tampered rules derive a different program and therefore a
		// different Guardian key; the real key must not match.
		if _, err := signConnectorGuardianStage(context.Background(), f.stored, f.guardianProg, auth); err == nil {
			t.Fatal("signed under unpinned fee rules")
		}
	})
	t.Run("wrong_guardian_key", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		emulatorProg := arkade.ComputeArkadeScriptPrivateKey(f.emulator, arkade.ArkadeScriptHash(f.family.Program))
		if emulatorProg == nil {
			t.Fatal("emulator program tweak is degenerate")
		}
		if _, err := signConnectorGuardianStage(context.Background(), f.stored, emulatorProg, f.auth); err == nil {
			t.Fatal("signed with the wrong cosigner key")
		}
	})
	t.Run("duplicate_enrolled_identity", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		if _, err := newConnectorGuardianAuthorization(
			f.phone.PubKey(), f.phone.PubKey(), f.emulator.PubKey(),
			f.family.Control, f.family.Rules.ConnectorScript, f.family.Rules,
		); err == nil {
			t.Fatal("accepted duplicate enrolled identities")
		}
	})
	t.Run("changed_control_block", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		control := packet.Inputs[connector.SavingsInput].TaprootLeafScript[0].ControlBlock
		control[len(control)-1] ^= 1
		// The phone signature commits the leaf, not the proof, so it stays
		// valid; rejection must come from the Merkle-proof check.
		if err := requirePresentConnectorSig(packet, connector.SavingsInput,
			schnorr.SerializePubKey(f.phone.PubKey()), f.family.Leaf); err != nil {
			t.Fatalf("phone signature should survive proof tampering: %v", err)
		}
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("Guardian signed a candidate with an invalid Savings Merkle proof")
		}
	})
	t.Run("foreign_internal_key_with_valid_phone_sig", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		other := newConnectorGuardianFixtureFor(t, "connector-guardian-foreign",
			connectorKey(23), connectorKey(24), connectorKey(25), connectorKey(26))
		packet := decodeConnectorStage(t, f.stored)
		// Transplant a well-formed proof from another enrollment (different
		// internal key and root) and pin it in the authorization, with a fresh
		// valid phone signature: the commitment check against the actual
		// Savings prevout must still reject it.
		packet.Inputs[connector.SavingsInput].TaprootLeafScript[0].ControlBlock = bytes.Clone(other.family.Control)
		signConnectorInputWithPhone(t, packet, f.phone, f.family.Leaf)
		auth, err := newConnectorGuardianAuthorization(
			f.phone.PubKey(), f.guardian.PubKey(), f.emulator.PubKey(),
			other.family.Control, f.family.Rules.ConnectorScript, f.family.Rules,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := requirePresentConnectorSig(packet, connector.SavingsInput,
			schnorr.SerializePubKey(f.phone.PubKey()), f.family.Leaf); err != nil {
			t.Fatalf("phone signature should survive proof transplant: %v", err)
		}
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, auth); err == nil {
			t.Fatal("Guardian signed a candidate whose proof does not commit the Savings prevout")
		}
	})
	t.Run("leaf_version_metadata_with_valid_phone_sig", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		// Only the PSBT metadata version is altered; control block, leaf, and
		// phone signature stay exactly as enrolled.
		packet.Inputs[connector.SavingsInput].TaprootLeafScript[0].LeafVersion = 0xc2
		if err := requirePresentConnectorSig(packet, connector.SavingsInput,
			schnorr.SerializePubKey(f.phone.PubKey()), f.family.Leaf); err != nil {
			t.Fatalf("phone signature should survive metadata tampering: %v", err)
		}
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("Guardian signed a candidate with an unexpected leaf version")
		}
	})
	t.Run("non_taproot_savings_prevout", func(t *testing.T) {
		f := newConnectorGuardianFixture(t)
		packet := decodeConnectorStage(t, f.stored)
		packet.Inputs[connector.SavingsInput].WitnessUtxo.PkScript = []byte{txscript.OP_0, 20, 1, 2, 3}
		if _, err := signConnectorGuardianStage(context.Background(), encodeConnectorStage(t, packet), f.guardianProg, f.auth); err == nil {
			t.Fatal("signed against a non-Taproot Savings prevout")
		}
	})
}
