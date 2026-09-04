package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

const (
	vaultBoardFinalDigestDomain = "arkade-vault/vault-board-v1-final-request/v1"
	maxVaultBoardTreeNodes      = 512
	maxVaultBoardTreeBytes      = maxJSONBody
	maxVaultBoardBatchIDBytes   = 256
)

// vaultBoardRecipientEvidence is the one BTC-only receiver the runtime must
// find in the independently validated shared VTXO tree. Other batch
// participants are allowed in the tree but are not caller-authorized outputs.
type vaultBoardRecipientEvidence struct {
	Script     []byte
	AmountSats int64
	HasAssets  bool
}

// vaultBoardFinalEvidence is private until the SDK adapter wire freezes.
// BatchExpiry is evidence, not policy: expectedExpiry below is the release pin.
type vaultBoardFinalEvidence struct {
	BatchID                string
	BatchExpiry            uint32
	SignedCommitmentPSBT   string
	UnsignedCommitmentPSBT string
	VtxoTree               arktree.FlatTxTree
	Recipients             []vaultBoardRecipientEvidence
	InputIndexes           []int
}

type verifiedVaultBoardFinal struct {
	CanonicalPSBT  string
	RequestDigest  []byte
	InputIndex     int
	CommitmentTxid string
	ReceiverTxid   string
	ReceiverVout   uint32
}

// verifyVaultBoardFinal independently binds the exact boarding input to the
// exact vault-policy-v1 output committed by the shared Batch Output. The SDK's
// prior validation is useful defense in depth but is never trusted here.
func verifyVaultBoardFinal(
	evidence vaultBoardFinalEvidence,
	operation policy.VaultBoardOperation,
	register policy.VaultBoardAuthorization,
	boardTree *vtxoBoardTree,
	expectedExpiry arklib.RelativeLocktime,
) (verifiedVaultBoardFinal, error) {
	if evidence.BatchID == "" || len(evidence.BatchID) > maxVaultBoardBatchIDBytes ||
		len(evidence.InputIndexes) != 1 || evidence.InputIndexes[0] < 0 ||
		expectedExpiry.Type != arklib.LocktimeTypeSecond || expectedExpiry.Value == 0 ||
		evidence.BatchExpiry != expectedExpiry.Value {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final batch policy")
	}
	if len(evidence.Recipients) != 1 || evidence.Recipients[0].HasAssets ||
		evidence.Recipients[0].AmountSats <= 0 ||
		register.Phase != policy.VaultBoardPhaseRegister || register.OperationID != operation.OperationID ||
		register.FeeSats < 0 || register.ReceiverSats > (1<<63-1)-register.FeeSats ||
		register.ReceiverSats != evidence.Recipients[0].AmountSats ||
		register.ReceiverSats+register.FeeSats != operation.ValueSats ||
		!bytes.Equal(evidence.Recipients[0].Script, operation.ReceiverScript) {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 exact receiver evidence required")
	}
	if boardTree == nil || boardTree.BoardingPub == nil || boardTree.CosignerPub == nil ||
		boardTree.OperatorPub == nil || len(boardTree.PkScript) != 34 ||
		!bytes.Equal(boardTree.PkScript, operation.BoardingScript) {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final boarding policy")
	}
	forfeitPubkey, err := hex.DecodeString(deployment.MutinynetCheckpointForfeitPubHex)
	if err != nil || len(forfeitPubkey) != btcec.PubKeyBytesLenCompressed {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 pinned forfeit key")
	}
	forfeit, err := btcec.ParsePubKey(forfeitPubkey)
	if err != nil {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 pinned forfeit key")
	}

	finalPacket, err := parseCanonicalVaultBoardPSBT(evidence.SignedCommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil {
		return verifiedVaultBoardFinal{}, err
	}
	unsignedPacket, err := parseCanonicalVaultBoardPSBT(evidence.UnsignedCommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil {
		return verifiedVaultBoardFinal{}, err
	}
	if finalPacket.UnsignedTx.TxHash() != unsignedPacket.UnsignedTx.TxHash() {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final commitment txid changed")
	}
	// Stock arkd builds the onchain commitment transaction at version 2.
	// Version 3 is reserved for Arkade offchain transactions and must not be
	// imposed on this Bitcoin transaction boundary.
	if finalPacket.UnsignedTx.Version != 2 {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final commitment version got=%d want=2", finalPacket.UnsignedTx.Version)
	}
	if finalPacket.UnsignedTx.LockTime != 0 {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final commitment locktime got=%d want=0", finalPacket.UnsignedTx.LockTime)
	}
	idx := evidence.InputIndexes[0]
	if idx >= len(finalPacket.Inputs) || idx >= len(finalPacket.UnsignedTx.TxIn) {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final input index")
	}
	if !vaultBoardOutpointMatches(operation, finalPacket.UnsignedTx.TxIn[idx].PreviousOutPoint) {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final outpoint")
	}
	for i := range finalPacket.Inputs {
		witness := finalPacket.Inputs[i].WitnessUtxo
		if witness == nil {
			return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final input %d prevout required", i)
		}
		if bytes.Equal(witness.PkScript, operation.BoardingScript) && i != idx {
			return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final contains another enrolled boarding input")
		}
	}
	input := finalPacket.Inputs[idx]
	if input.WitnessUtxo == nil || input.WitnessUtxo.Value != operation.ValueSats ||
		!bytes.Equal(input.WitnessUtxo.PkScript, operation.BoardingScript) {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final prevout")
	}
	boardingXOnly := schnorr.SerializePubKey(boardTree.BoardingPub)
	if err := requireExactLeafWithSighash(input, boardTree.PkScript, boardTree.Collaborative, boardTree.ControlBlock, [][]byte{boardingXOnly}, txscript.SigHashDefault); err != nil {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final leaf: %w", err)
	}
	if err := requireVerifiedSignersWithSighash(finalPacket, idx, [][]byte{boardingXOnly}, boardTree.Collaborative, txscript.SigHashDefault); err != nil {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 final boarding signature: %w", err)
	}

	flat, err := canonicalVaultBoardTree(evidence.VtxoTree)
	if err != nil {
		return verifiedVaultBoardFinal{}, err
	}
	txTree, err := arktree.NewTxTree(flat)
	if err != nil {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 VTXO tree: %w", err)
	}
	if err := arktree.ValidateVtxoTree(txTree, unsignedPacket, forfeit, expectedExpiry); err != nil {
		return verifiedVaultBoardFinal{}, fmt.Errorf("vault-board-v1 VTXO tree policy: %w", err)
	}
	receiverTxid, receiverVout, err := findExactVaultBoardReceiver(txTree, operation.ReceiverScript, evidence.Recipients[0].AmountSats)
	if err != nil {
		return verifiedVaultBoardFinal{}, err
	}
	digest, err := vaultBoardFinalRequestDigest(evidence, flat)
	if err != nil {
		return verifiedVaultBoardFinal{}, err
	}
	return verifiedVaultBoardFinal{
		CanonicalPSBT:  evidence.SignedCommitmentPSBT,
		RequestDigest:  digest,
		InputIndex:     idx,
		CommitmentTxid: finalPacket.UnsignedTx.TxID(),
		ReceiverTxid:   receiverTxid,
		ReceiverVout:   receiverVout,
	}, nil
}

func parseCanonicalVaultBoardPSBT(raw string, max int) (*psbt.Packet, error) {
	if len(raw) == 0 || len(raw) > max {
		return nil, fmt.Errorf("vault-board-v1 PSBT size")
	}
	packet, err := parsePSBT(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := packet.B64Encode()
	if err != nil || canonical != raw {
		return nil, fmt.Errorf("vault-board-v1 PSBT must use canonical base64 encoding")
	}
	if len(packet.Outputs) != len(packet.UnsignedTx.TxOut) {
		return nil, fmt.Errorf("vault-board-v1 PSBT output count")
	}
	return packet, nil
}

func canonicalVaultBoardTree(flat arktree.FlatTxTree) (arktree.FlatTxTree, error) {
	if len(flat) == 0 || len(flat) > maxVaultBoardTreeNodes {
		return nil, fmt.Errorf("vault-board-v1 VTXO tree size")
	}
	out := make(arktree.FlatTxTree, len(flat))
	total := 0
	seen := make(map[string]struct{}, len(flat))
	for i, node := range flat {
		if requireTxid(node.Txid) != nil || len(node.Tx) == 0 || len(node.Tx) > maxVaultBoardProofBytes {
			return nil, fmt.Errorf("vault-board-v1 VTXO tree node")
		}
		packet, err := parseCanonicalVaultBoardPSBT(node.Tx, maxVaultBoardProofBytes)
		if err != nil || packet.UnsignedTx.TxID() != node.Txid {
			return nil, fmt.Errorf("vault-board-v1 VTXO tree node txid")
		}
		if _, duplicate := seen[node.Txid]; duplicate {
			return nil, fmt.Errorf("vault-board-v1 duplicate VTXO tree node")
		}
		seen[node.Txid] = struct{}{}
		total += len(node.Tx) + len(node.Txid) + len(node.Children)*72
		if total > maxVaultBoardTreeBytes {
			return nil, fmt.Errorf("vault-board-v1 VTXO tree size")
		}
		children := make(map[uint32]string, len(node.Children))
		for index, child := range node.Children {
			if requireTxid(child) != nil {
				return nil, fmt.Errorf("vault-board-v1 VTXO tree child")
			}
			children[index] = child
		}
		out[i] = arktree.TxTreeNode{Txid: node.Txid, Tx: node.Tx, Children: children}
	}
	for _, node := range out {
		for _, child := range node.Children {
			if _, ok := seen[child]; !ok {
				return nil, fmt.Errorf("vault-board-v1 VTXO tree child missing")
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Txid < out[j].Txid })
	return out, nil
}

func findExactVaultBoardReceiver(txTree *arktree.TxTree, script []byte, amount int64) (string, uint32, error) {
	if txTree == nil || len(script) == 0 || amount <= 0 {
		return "", 0, fmt.Errorf("vault-board-v1 receiver policy")
	}
	var txid string
	var vout uint32
	matches := 0
	for _, leaf := range txTree.Leaves() {
		for index, output := range leaf.UnsignedTx.TxOut {
			if !bytes.Equal(output.PkScript, script) {
				continue
			}
			matches++
			if output.Value != amount {
				return "", 0, fmt.Errorf("vault-board-v1 receiver amount conflict")
			}
			txid = leaf.UnsignedTx.TxID()
			vout = uint32(index)
		}
	}
	if matches != 1 {
		return "", 0, fmt.Errorf("vault-board-v1 receiver must appear exactly once")
	}
	return txid, vout, nil
}

func vaultBoardFinalRequestDigest(evidence vaultBoardFinalEvidence, flat arktree.FlatTxTree) ([]byte, error) {
	if len(evidence.Recipients) != 1 || len(evidence.InputIndexes) != 1 {
		return nil, fmt.Errorf("vault-board-v1 final digest evidence")
	}
	h := sha256.New()
	writeVaultBoardDigestField(h, []byte(vaultBoardFinalDigestDomain))
	writeVaultBoardDigestField(h, []byte(evidence.BatchID))
	writeVaultBoardDigestField(h, []byte(evidence.SignedCommitmentPSBT))
	writeVaultBoardDigestField(h, []byte(evidence.UnsignedCommitmentPSBT))
	var value [8]byte
	binary.LittleEndian.PutUint32(value[:4], uint32(len(flat)))
	_, _ = h.Write(value[:4])
	binary.LittleEndian.PutUint32(value[:4], evidence.BatchExpiry)
	_, _ = h.Write(value[:4])
	binary.LittleEndian.PutUint32(value[:4], uint32(evidence.InputIndexes[0]))
	_, _ = h.Write(value[:4])
	for _, node := range flat {
		writeVaultBoardDigestField(h, []byte(node.Txid))
		writeVaultBoardDigestField(h, []byte(node.Tx))
		binary.LittleEndian.PutUint32(value[:4], uint32(len(node.Children)))
		_, _ = h.Write(value[:4])
		indexes := make([]uint32, 0, len(node.Children))
		for index := range node.Children {
			indexes = append(indexes, index)
		}
		sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
		for _, index := range indexes {
			binary.LittleEndian.PutUint32(value[:4], index)
			_, _ = h.Write(value[:4])
			writeVaultBoardDigestField(h, []byte(node.Children[index]))
		}
	}
	writeVaultBoardDigestField(h, evidence.Recipients[0].Script)
	binary.LittleEndian.PutUint64(value[:], uint64(evidence.Recipients[0].AmountSats))
	_, _ = h.Write(value[:])
	return h.Sum(nil), nil
}
