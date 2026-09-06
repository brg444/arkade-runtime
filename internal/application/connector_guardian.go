package application

import (
	"bytes"
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// connectorGuardianAuthorization pins the exact Guardian signing contract for
// one enrolled Savings connector candidate. The caller supplies only the
// enrolled identities (phone, both cosigner bases), the enrolled control
// block, the enrolled connector script, and the fee rules. Everything else is
// derived inside this boundary: the program, both program-tweaked authorities,
// the expected Guardian key, and the expected normal leaf. Caller-supplied
// keys or rules can therefore never become an authorization oracle — any
// substituted program changes the tweaked Guardian key, which the real private
// key will not match.
//
// The exact stored candidate snapshot remains the authority for transaction
// data: every call re-validates the full connector program and the Savings
// leaf/control-block commitment against the verified prevout script.
//
// This helper is intentionally not a generic multi-input signer. It signs only
// input 0 (the Savings input) and only when the transaction is a valid
// connector candidate whose phone signature is already present. It is not
// wired to any endpoint, profile, or key capability yet.
type connectorGuardianAuthorization struct {
	phone, guardianBase, emulatorBase *btcec.PublicKey
	phoneExpectedXOnly                []byte
	guardianExpectedXOnly             []byte
	spendLeaf                         []byte
	controlBlock                      []byte
	connectorScript                   []byte
	rules                             connector.Rules
}

func newConnectorGuardianAuthorization(
	phone, guardianBase, emulatorBase *btcec.PublicKey,
	controlBlock, connectorScript []byte,
	rules connector.Rules,
) (connectorGuardianAuthorization, error) {
	if phone == nil || guardianBase == nil || emulatorBase == nil {
		return connectorGuardianAuthorization{}, fmt.Errorf("connector enrolled signing authorities required")
	}
	compressed := [][]byte{phone.SerializeCompressed(), guardianBase.SerializeCompressed(), emulatorBase.SerializeCompressed()}
	for i, key := range compressed {
		for _, other := range compressed[:i] {
			if bytes.Equal(key, other) {
				return connectorGuardianAuthorization{}, fmt.Errorf("distinct connector enrolled identities required")
			}
		}
	}
	if len(controlBlock) == 0 || len(connectorScript) == 0 {
		return connectorGuardianAuthorization{}, fmt.Errorf("connector Guardian authorization required")
	}
	if !bytes.Equal(rules.ConnectorScript, connectorScript) {
		return connectorGuardianAuthorization{}, fmt.Errorf("connector rules script mismatch")
	}
	control, err := txscript.ParseControlBlock(controlBlock)
	if err != nil {
		return connectorGuardianAuthorization{}, fmt.Errorf("connector control block: %w", err)
	}
	if control.LeafVersion != txscript.BaseLeafVersion {
		return connectorGuardianAuthorization{}, fmt.Errorf("unexpected connector leaf version")
	}
	program, err := connector.BuildProgram(rules)
	if err != nil {
		return connectorGuardianAuthorization{}, err
	}
	hash := arkade.ArkadeScriptHash(program)
	guardianTweaked := arkade.ComputeArkadeScriptPublicKey(guardianBase, hash)
	emulatorTweaked := arkade.ComputeArkadeScriptPublicKey(emulatorBase, hash)
	if guardianTweaked == nil || emulatorTweaked == nil {
		return connectorGuardianAuthorization{}, fmt.Errorf("connector program tweak is degenerate")
	}
	tweaked := [][]byte{
		schnorr.SerializePubKey(phone),
		schnorr.SerializePubKey(guardianTweaked),
		schnorr.SerializePubKey(emulatorTweaked),
	}
	for i, key := range tweaked {
		for _, other := range tweaked[:i] {
			if bytes.Equal(key, other) {
				return connectorGuardianAuthorization{}, fmt.Errorf("distinct connector signing authorities required")
			}
		}
	}
	leaf, err := savings.Checksig(phone, guardianTweaked, emulatorTweaked)
	if err != nil {
		return connectorGuardianAuthorization{}, err
	}
	return connectorGuardianAuthorization{
		phone: phone, guardianBase: guardianBase, emulatorBase: emulatorBase,
		phoneExpectedXOnly:    bytes.Clone(tweaked[0]),
		guardianExpectedXOnly: bytes.Clone(tweaked[1]),
		spendLeaf:             leaf,
		controlBlock:          bytes.Clone(controlBlock),
		connectorScript:       bytes.Clone(connectorScript),
		rules: connector.Rules{
			ConnectorScript:    bytes.Clone(rules.ConnectorScript),
			WitnessBytes:       rules.WitnessBytes,
			AbsoluteFeeCapSats: rules.AbsoluteFeeCapSats,
			FeerateCapSatPerV:  rules.FeerateCapSatPerV,
		},
	}, nil
}

// signConnectorGuardianStage adds exactly one Guardian Taproot script-spend
// signature to input 0 of the exact stored connector candidate and returns the
// re-encoded snapshot. The phone signature must already be present and valid;
// the Guardian key signs only after the full candidate program and the Savings
// Merkle proof validate. The returned packet is built from a clone of the
// submitted snapshot, so signer or caller mutations can never redefine the
// authorized transaction.
func signConnectorGuardianStage(
	ctx context.Context,
	stored string,
	priv *btcec.PrivateKey,
	auth connectorGuardianAuthorization,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if auth.phone == nil || auth.guardianBase == nil || auth.emulatorBase == nil ||
		len(auth.guardianExpectedXOnly) != schnorr.PubKeyBytesLen || len(auth.spendLeaf) == 0 || len(auth.controlBlock) == 0 {
		return "", fmt.Errorf("connector Guardian authorization required")
	}
	if priv == nil || !bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), auth.guardianExpectedXOnly) {
		return "", fmt.Errorf("connector Guardian signer key mismatch")
	}
	submitted, err := parsePSBT(stored)
	if err != nil {
		return "", err
	}
	if len(submitted.Inputs) != 2 || len(submitted.UnsignedTx.TxIn) != 2 {
		return "", fmt.Errorf("connector transaction requires exactly two inputs")
	}
	if n := len(submitted.UnsignedTx.TxOut); n != 4 && n != 5 {
		return "", fmt.Errorf("connector transaction shape")
	}
	parents, err := requireConnectorPrevouts(submitted)
	if err != nil {
		return "", err
	}
	reserve := submitted.Inputs[connector.ConnectorInput].WitnessUtxo
	if reserve.Value != connector.ReserveSats || !bytes.Equal(reserve.PkScript, auth.connectorScript) {
		return "", fmt.Errorf("connector reserve input mismatch")
	}
	savingsPrev := submitted.Inputs[connector.SavingsInput].WitnessUtxo
	if !isConnectorP2TR(savingsPrev.PkScript) {
		return "", fmt.Errorf("connector Savings prevout script")
	}
	savings := submitted.Inputs[connector.SavingsInput]
	if len(savings.TaprootLeafScript) != 1 || savings.TaprootLeafScript[0] == nil {
		return "", fmt.Errorf("connector Savings leaf required")
	}
	entry := savings.TaprootLeafScript[0]
	if entry.LeafVersion != txscript.BaseLeafVersion {
		return "", fmt.Errorf("unexpected connector leaf version")
	}
	if !bytes.Equal(entry.Script, auth.spendLeaf) {
		return "", fmt.Errorf("connector Savings leaf mismatch")
	}
	// The Merkle proof is verified against the actual verified Savings prevout
	// script, not against caller claims. PSBT leaf metadata alone proves
	// nothing; a tampered control block, leaf version, or internal key fails
	// here even when the phone signature over the leaf remains valid.
	if !bytes.Equal(entry.ControlBlock, auth.controlBlock) {
		return "", fmt.Errorf("connector Savings proof mismatch")
	}
	control, err := txscript.ParseControlBlock(entry.ControlBlock)
	if err != nil {
		return "", fmt.Errorf("connector Savings proof: %w", err)
	}
	if control.LeafVersion != txscript.BaseLeafVersion {
		return "", fmt.Errorf("unexpected connector leaf version")
	}
	if err := txscript.VerifyTaprootLeafCommitment(control, savingsPrev.PkScript[2:], auth.spendLeaf); err != nil {
		return "", fmt.Errorf("connector Savings proof: %w", err)
	}
	if savings.SighashType != txscript.SigHashDefault {
		return "", fmt.Errorf("connector Savings requires DEFAULT sighash")
	}
	if err := requirePresentConnectorSig(submitted, connector.SavingsInput, auth.phoneExpectedXOnly, auth.spendLeaf); err != nil {
		return "", fmt.Errorf("connector phone signature: %w", err)
	}
	for _, existing := range savings.TaprootScriptSpendSig {
		if existing != nil && bytes.Equal(existing.XOnlyPubKey, auth.guardianExpectedXOnly) {
			return "", fmt.Errorf("connector Guardian signature already present")
		}
	}
	if err := connector.Validate(auth.rules, submitted.UnsignedTx, parents); err != nil {
		return "", fmt.Errorf("connector program: %w", err)
	}
	work, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	added, err := signTapLeafAtWithSighash(work, connector.SavingsInput, priv, auth.spendLeaf, txscript.SigHashDefault)
	if err != nil {
		return "", err
	}
	if err := verifySchnorrOnInputWithSighash(
		submitted, connector.SavingsInput, added.Signature,
		auth.guardianExpectedXOnly, auth.spendLeaf, txscript.SigHashDefault,
	); err != nil {
		return "", fmt.Errorf("connector Guardian signature invalid")
	}
	out, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	out.Inputs[connector.SavingsInput].TaprootScriptSpendSig = append(
		out.Inputs[connector.SavingsInput].TaprootScriptSpendSig, added,
	)
	return out.B64Encode()
}

func isConnectorP2TR(script []byte) bool {
	if len(script) != 34 || script[0] != txscript.OP_1 || script[1] != 32 {
		return false
	}
	_, err := schnorr.ParsePubKey(script[2:])
	return err == nil
}

// requireConnectorPrevouts verifies parent data for both connector inputs. The
// existing one-input RequireVerifiedPrevout is deliberately left untouched so
// the recovery boundary keeps its exact shape; this scoped check covers only
// the named two-input connector transaction.
func requireConnectorPrevouts(ptx *psbt.Packet) (connector.Parents, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 2 || len(ptx.UnsignedTx.TxIn) != 2 {
		return nil, fmt.Errorf("connector transaction requires exactly two inputs")
	}
	parents := make(connector.Parents, 2)
	for i := range ptx.Inputs {
		in := ptx.Inputs[i]
		op := ptx.UnsignedTx.TxIn[i].PreviousOutPoint
		if in.WitnessUtxo == nil || in.NonWitnessUtxo == nil {
			return nil, fmt.Errorf("connector input %d prevout required", i)
		}
		parent := in.NonWitnessUtxo
		if parent.TxHash() != op.Hash || int(op.Index) >= len(parent.TxOut) {
			return nil, fmt.Errorf("connector input %d parent mismatch", i)
		}
		want := parent.TxOut[op.Index]
		if want == nil || want.Value != in.WitnessUtxo.Value || !bytes.Equal(want.PkScript, in.WitnessUtxo.PkScript) {
			return nil, fmt.Errorf("connector input %d witness utxo does not match prevout", i)
		}
		fields, err := txutils.GetArkPsbtFields(ptx, i, arkade.PrevoutTxField)
		if err != nil {
			return nil, err
		}
		if len(fields) != 1 {
			return nil, fmt.Errorf("connector input %d PrevoutTxField required", i)
		}
		pinned := fields[0]
		if pinned.TxHash() != op.Hash || int(op.Index) >= len(pinned.TxOut) {
			return nil, fmt.Errorf("connector input %d pinned parent mismatch", i)
		}
		pinnedOut := pinned.TxOut[op.Index]
		if pinnedOut == nil || pinnedOut.Value != in.WitnessUtxo.Value || !bytes.Equal(pinnedOut.PkScript, in.WitnessUtxo.PkScript) {
			return nil, fmt.Errorf("connector input %d pinned prevout mismatch", i)
		}
		cp := pinned.Copy()
		parents[op] = cp
	}
	return parents, nil
}

// requirePresentConnectorSig verifies that the expected signer already has a
// valid DEFAULT signature on the given input of the submitted snapshot.
func requirePresentConnectorSig(ptx *psbt.Packet, index int, expectedXOnly, leafScript []byte) error {
	if ptx == nil || index < 0 || index >= len(ptx.Inputs) {
		return fmt.Errorf("input index")
	}
	leaf := txscript.NewBaseTapLeaf(leafScript)
	leafHash := leaf.TapHash()
	for _, existing := range ptx.Inputs[index].TaprootScriptSpendSig {
		if existing == nil || len(existing.Signature) != 64 {
			continue
		}
		if !bytes.Equal(existing.XOnlyPubKey, expectedXOnly) || !bytes.Equal(existing.LeafHash, leafHash[:]) {
			continue
		}
		if existing.SigHash != txscript.SigHashDefault {
			continue
		}
		return verifySchnorrOnInputWithSighash(ptx, index, existing.Signature, expectedXOnly, leafScript, txscript.SigHashDefault)
	}
	return fmt.Errorf("expected signer signature missing")
}
