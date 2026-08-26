package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	vaultBoardIntentDigestDomain = "arkade-vault/vault-board-v1-intent-request/v1"
	maxVaultBoardProofBytes      = 256 * 1024
)

type verifiedVaultBoardIntentProof struct {
	CanonicalPSBT string
	Message       string
	RequestDigest []byte
	InputIndexes  []int
	ExpireAt      int64
	TreeSession   []byte
	ReceiverSats  int64
	FeeSats       int64
}

func verifyVaultBoardRegisterProof(
	raw, message string,
	operation policy.VaultBoardOperation,
	tree *vtxoBoardTree,
	expectedExpireAt int64,
) (verifiedVaultBoardIntentProof, error) {
	var register intent.RegisterMessage
	if err := register.Decode(message); err != nil {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 register message")
	}
	canonical, err := register.Encode()
	if err != nil || canonical != message || register.OnchainOutputIndexes == nil || len(register.OnchainOutputIndexes) != 0 ||
		register.ValidAt != 0 || register.ExpireAt != expectedExpireAt || expectedExpireAt <= 0 || len(register.CosignersPublicKeys) != 1 {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 canonical register message")
	}
	treeSession, err := hex.DecodeString(register.CosignersPublicKeys[0])
	if err != nil || len(treeSession) != btcec.PubKeyBytesLenCompressed || hex.EncodeToString(treeSession) != register.CosignersPublicKeys[0] {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 tree session key")
	}
	if _, err := btcec.ParsePubKey(treeSession); err != nil {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 tree session key")
	}

	packet, err := verifyVaultBoardIntentProofShape(raw, message, operation, tree, true)
	if err != nil {
		return verifiedVaultBoardIntentProof{}, err
	}
	receiver := packet.UnsignedTx.TxOut[0]
	if receiver.Value <= 0 || receiver.Value > operation.ValueSats || !bytes.Equal(receiver.PkScript, operation.ReceiverScript) {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 register receiver")
	}
	fee := operation.ValueSats - receiver.Value
	digest, err := vaultBoardIntentRequestDigest(policy.VaultBoardPhaseRegister, packet, message, []int{0, 1})
	if err != nil {
		return verifiedVaultBoardIntentProof{}, err
	}
	return verifiedVaultBoardIntentProof{
		CanonicalPSBT: raw, Message: message, RequestDigest: digest,
		InputIndexes: []int{0, 1}, ExpireAt: expectedExpireAt,
		TreeSession: treeSession, ReceiverSats: receiver.Value, FeeSats: fee,
	}, nil
}

func verifyVaultBoardDeleteProof(
	raw, message string,
	operation policy.VaultBoardOperation,
	tree *vtxoBoardTree,
	expectedExpireAt int64,
) (verifiedVaultBoardIntentProof, error) {
	var deletion intent.DeleteMessage
	if err := deletion.Decode(message); err != nil {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 delete message")
	}
	canonical, err := deletion.Encode()
	if err != nil || canonical != message || deletion.ExpireAt != expectedExpireAt || expectedExpireAt <= 0 {
		return verifiedVaultBoardIntentProof{}, fmt.Errorf("vault-board-v1 canonical delete message")
	}
	packet, err := verifyVaultBoardIntentProofShape(raw, message, operation, tree, false)
	if err != nil {
		return verifiedVaultBoardIntentProof{}, err
	}
	digest, err := vaultBoardIntentRequestDigest(policy.VaultBoardPhaseDelete, packet, message, []int{0, 1})
	if err != nil {
		return verifiedVaultBoardIntentProof{}, err
	}
	return verifiedVaultBoardIntentProof{
		CanonicalPSBT: raw, Message: message, RequestDigest: digest,
		InputIndexes: []int{0, 1}, ExpireAt: expectedExpireAt,
	}, nil
}

func verifyVaultBoardIntentProofShape(
	raw, message string,
	operation policy.VaultBoardOperation,
	tree *vtxoBoardTree,
	register bool,
) (*psbt.Packet, error) {
	if len(raw) == 0 || len(raw) > maxVaultBoardProofBytes || tree == nil || tree.BoardingPub == nil ||
		tree.CosignerPub == nil || tree.OperatorPub == nil || len(tree.PkScript) != 34 ||
		len(tree.Collaborative) == 0 || len(tree.ControlBlock) == 0 || len(tree.RevealedScripts) == 0 {
		return nil, fmt.Errorf("vault-board-v1 proof policy required")
	}
	packet, err := parsePSBT(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := packet.B64Encode()
	if err != nil || canonical != raw {
		return nil, fmt.Errorf("vault-board-v1 proof must use canonical base64 PSBT encoding")
	}
	if len(packet.Unknowns) != 1 || packet.Unknowns[0] == nil ||
		!bytes.Equal(packet.Unknowns[0].Key, []byte{0x09}) || !bytes.Equal(packet.Unknowns[0].Value, []byte(message)) {
		return nil, fmt.Errorf("vault-board-v1 proof canonical message required")
	}
	if packet.UnsignedTx.Version != 2 || packet.UnsignedTx.LockTime != 0 ||
		len(packet.UnsignedTx.TxIn) != 2 || len(packet.Inputs) != 2 {
		return nil, fmt.Errorf("vault-board-v1 proof transaction shape")
	}
	if register {
		if len(packet.UnsignedTx.TxOut) != 1 || len(packet.Outputs) != 1 {
			return nil, fmt.Errorf("vault-board-v1 register output count")
		}
	} else if len(packet.UnsignedTx.TxOut) != 1 || len(packet.Outputs) != 1 ||
		packet.UnsignedTx.TxOut[0].Value != 0 || !bytes.Equal(packet.UnsignedTx.TxOut[0].PkScript, []byte{txscript.OP_RETURN}) {
		return nil, fmt.Errorf("vault-board-v1 delete outputs")
	}
	if !vaultBoardOutpointMatches(operation, packet.UnsignedTx.TxIn[1].PreviousOutPoint) {
		return nil, fmt.Errorf("vault-board-v1 proof outpoint")
	}
	boardingXOnly := schnorr.SerializePubKey(tree.BoardingPub)
	for i := range packet.Inputs {
		if packet.UnsignedTx.TxIn[i].Sequence != wire.MaxTxInSequenceNum {
			return nil, fmt.Errorf("vault-board-v1 proof sequence")
		}
		wantValue := int64(0)
		if i == 1 {
			wantValue = operation.ValueSats
		}
		witness := packet.Inputs[i].WitnessUtxo
		if witness == nil || witness.Value != wantValue || !bytes.Equal(witness.PkScript, operation.BoardingScript) ||
			!bytes.Equal(witness.PkScript, tree.PkScript) {
			return nil, fmt.Errorf("vault-board-v1 proof input %d prevout", i)
		}
		if err := requireExactLeafWithSighash(packet.Inputs[i], tree.PkScript, tree.Collaborative, tree.ControlBlock, [][]byte{boardingXOnly}, txscript.SigHashAll); err != nil {
			return nil, fmt.Errorf("vault-board-v1 proof input %d: %w", i, err)
		}
		if err := requireVerifiedSignersWithSighash(packet, i, [][]byte{boardingXOnly}, tree.Collaborative, txscript.SigHashAll); err != nil {
			return nil, fmt.Errorf("vault-board-v1 proof input %d: %w", i, err)
		}
		fields, err := txutils.GetArkPsbtFields(packet, i, txutils.VtxoTaprootTreeField)
		if err != nil || len(fields) != 1 || len(fields[0]) != len(tree.RevealedScripts) {
			return nil, fmt.Errorf("vault-board-v1 proof input %d revealed tree", i)
		}
		for j := range tree.RevealedScripts {
			if fields[0][j] != tree.RevealedScripts[j] {
				return nil, fmt.Errorf("vault-board-v1 proof input %d revealed tree", i)
			}
		}
	}
	if err := intent.Verify(raw, message, []*btcec.PublicKey{tree.CosignerPub, tree.OperatorPub}); err != nil {
		return nil, fmt.Errorf("vault-board-v1 proof invalid: %w", err)
	}
	return packet, nil
}

func vaultBoardOutpointMatches(operation policy.VaultBoardOperation, outpoint wire.OutPoint) bool {
	return len(operation.Txid) == 32 && hex.EncodeToString(operation.Txid) == outpoint.Hash.String() &&
		operation.Vout == outpoint.Index
}

func vaultBoardIntentRequestDigest(phase string, packet *psbt.Packet, message string, inputIndexes []int) ([]byte, error) {
	if packet == nil || packet.UnsignedTx == nil || len(inputIndexes) != 2 || inputIndexes[0] != 0 || inputIndexes[1] != 1 {
		return nil, fmt.Errorf("vault-board-v1 proof input indexes")
	}
	// The request identity binds the canonical unsigned proof semantics, not a
	// randomized partial Schnorr encoding. This makes an exact retry safe after
	// a client reload without weakening the separately verified BoardingPub
	// signature gate.
	unsigned, err := clonePacket(packet)
	if err != nil {
		return nil, err
	}
	for i := range unsigned.Inputs {
		unsigned.Inputs[i].TaprootScriptSpendSig = nil
	}
	raw, err := unsigned.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 proof encoding")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(decoded) > maxVaultBoardProofBytes {
		zeroServiceBytes(decoded)
		return nil, fmt.Errorf("vault-board-v1 proof encoding")
	}
	h := sha256.New()
	writeVaultBoardDigestField(h, []byte(vaultBoardIntentDigestDomain))
	writeVaultBoardDigestField(h, []byte(phase))
	writeVaultBoardDigestField(h, decoded)
	writeVaultBoardDigestField(h, []byte(message))
	var index [4]byte
	for _, value := range inputIndexes {
		binary.LittleEndian.PutUint32(index[:], uint32(value))
		_, _ = h.Write(index[:])
	}
	zeroServiceBytes(decoded)
	return h.Sum(nil), nil
}

func writeVaultBoardDigestField(h interface{ Write([]byte) (int, error) }, value []byte) {
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}
