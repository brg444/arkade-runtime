package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const canonicalGetPendingTxMessage = `{"type":"get-pending-tx","expire_at":0}`

func pendingProofDigest(raw string) ([]byte, error) {
	packet, err := parsePSBT(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := packet.B64Encode()
	if err != nil {
		return nil, err
	}
	if canonical != raw {
		return nil, fmt.Errorf("pending proof must use canonical base64 PSBT encoding")
	}
	decoded, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		return nil, fmt.Errorf("pending proof encoding")
	}
	digest := sha256.Sum256(decoded)
	return digest[:], nil
}

func verifyPhonePendingProof(
	raw string,
	inputs []policy.VtxoOperationInput,
	tree *vtxoPolicyTree,
	phone *btcec.PublicKey,
) error {
	if phone == nil || tree == nil || tree.CosignerPub == nil || tree.ArkdPub == nil {
		return fmt.Errorf("pending proof signer policy required")
	}
	return verifyPendingProof(
		raw, inputs, tree,
		[]*btcec.PublicKey{phone},
		[]*btcec.PublicKey{tree.CosignerPub, tree.ArkdPub},
	)
}

func verifyDualSignedPendingProof(
	raw string,
	inputs []policy.VtxoOperationInput,
	tree *vtxoPolicyTree,
	phone *btcec.PublicKey,
) error {
	if phone == nil || tree == nil || tree.CosignerPub == nil || tree.ArkdPub == nil {
		return fmt.Errorf("pending proof signer policy required")
	}
	return verifyPendingProof(
		raw, inputs, tree,
		[]*btcec.PublicKey{phone, tree.CosignerPub},
		[]*btcec.PublicKey{tree.ArkdPub},
	)
}

func verifyPendingProof(
	raw string,
	inputs []policy.VtxoOperationInput,
	tree *vtxoPolicyTree,
	required, skipped []*btcec.PublicKey,
) error {
	if len(inputs) == 0 || tree == nil || len(tree.PkScript) == 0 || len(tree.SpendLeaf) == 0 {
		return fmt.Errorf("pending proof policy inputs required")
	}
	packet, err := parsePSBT(raw)
	if err != nil {
		return err
	}
	canonical, err := packet.B64Encode()
	if err != nil || canonical != raw {
		return fmt.Errorf("pending proof must use canonical base64 PSBT encoding")
	}
	if err := requirePendingProofMessage(packet); err != nil {
		return err
	}
	if packet.UnsignedTx.Version != 2 || packet.UnsignedTx.LockTime != 0 {
		return fmt.Errorf("pending proof version/locktime")
	}
	if len(packet.UnsignedTx.TxIn) != len(inputs)+1 || len(packet.Inputs) != len(inputs)+1 {
		return fmt.Errorf("pending proof input count")
	}
	if len(packet.UnsignedTx.TxOut) != 1 || len(packet.Outputs) != 1 ||
		packet.UnsignedTx.TxOut[0].Value != 0 ||
		!bytes.Equal(packet.UnsignedTx.TxOut[0].PkScript, []byte{txscript.OP_RETURN}) {
		return fmt.Errorf("pending proof outputs")
	}

	requiredXOnly := make([][]byte, len(required))
	for i, pub := range required {
		if pub == nil {
			return fmt.Errorf("pending proof required signer")
		}
		requiredXOnly[i] = schnorr.SerializePubKey(pub)
	}
	for i := range packet.Inputs {
		if packet.UnsignedTx.TxIn[i].Sequence != wire.MaxTxInSequenceNum {
			return fmt.Errorf("pending proof sequence")
		}
		wantValue := int64(0)
		wantScript := tree.PkScript
		if i > 0 {
			stored := inputs[i-1]
			if _, ok := matchReservedOutpoint(map[string]policy.VtxoOperationInput{
				outpointKey(stored.Txid, uint32(stored.Vout)): stored,
			}, packet.UnsignedTx.TxIn[i].PreviousOutPoint); !ok {
				return fmt.Errorf("pending proof input order")
			}
			wantValue = stored.ValueSats
			wantScript = stored.Script
		}
		witness := packet.Inputs[i].WitnessUtxo
		if witness == nil || witness.Value != wantValue ||
			!bytes.Equal(witness.PkScript, tree.PkScript) || !bytes.Equal(witness.PkScript, wantScript) {
			return fmt.Errorf("pending proof input %d prevout", i)
		}
		if err := requireExactLeafWithSighash(
			packet.Inputs[i], tree.PkScript, tree.SpendLeaf, tree.SpendControl,
			requiredXOnly, txscript.SigHashAll,
		); err != nil {
			return fmt.Errorf("pending proof input %d: %w", i, err)
		}
		if err := requireVerifiedSignersWithSighash(
			packet, i, requiredXOnly, tree.SpendLeaf, txscript.SigHashAll,
		); err != nil {
			return fmt.Errorf("pending proof input %d: %w", i, err)
		}
	}

	if err := intent.Verify(raw, canonicalGetPendingTxMessage, skipped); err != nil {
		return fmt.Errorf("pending proof invalid: %w", err)
	}
	return nil
}

func requirePendingProofMessage(packet *psbt.Packet) error {
	if packet == nil {
		return fmt.Errorf("pending proof required")
	}
	if len(packet.Unknowns) != 1 || packet.Unknowns[0] == nil ||
		!bytes.Equal(packet.Unknowns[0].Key, []byte{0x09}) {
		return fmt.Errorf("pending proof canonical message required")
	}
	if !bytes.Equal(packet.Unknowns[0].Value, []byte(canonicalGetPendingTxMessage)) {
		return fmt.Errorf("pending proof message")
	}
	return nil
}

func requireOnlyVaultSignatureAdded(beforeRaw, afterRaw string, expectedVault []byte) error {
	before, err := parsePSBT(beforeRaw)
	if err != nil {
		return err
	}
	after, err := parsePSBT(afterRaw)
	if err != nil {
		return err
	}
	if len(before.Inputs) != len(after.Inputs) || len(expectedVault) != 32 {
		return fmt.Errorf("authorized pending proof shape")
	}
	for i := range after.Inputs {
		var kept []*psbt.TaprootScriptSpendSig
		added := 0
		for _, sig := range after.Inputs[i].TaprootScriptSpendSig {
			if sig != nil && bytes.Equal(sig.XOnlyPubKey, expectedVault) {
				added++
				continue
			}
			kept = append(kept, sig)
		}
		if added != 1 {
			return fmt.Errorf("expected one VaultCosigner signature on pending proof input %d", i)
		}
		after.Inputs[i].TaprootScriptSpendSig = kept
	}
	stripped, err := after.B64Encode()
	if err != nil {
		return err
	}
	if stripped != beforeRaw {
		return fmt.Errorf("authorized pending proof mutated phone proof")
	}
	return nil
}
