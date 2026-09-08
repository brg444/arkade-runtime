package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// All replacement paths and source forfeits are one immutable final request.
// This evidence must be retained before the Guardian can sign any forfeit.
type rollingRenewalFinalEvidence struct {
	BatchID        string             `json:"batchId"`
	BatchExpiry    uint32             `json:"batchExpiry"`
	CommitmentPSBT string             `json:"commitmentPsbt"`
	VtxoTree       arktree.FlatTxTree `json:"vtxoTree"`
	Connectors     arktree.FlatTxTree `json:"connectors"`
	ForfeitPSBTs   []string           `json:"forfeitPsbts"`
}

type verifiedRollingRenewalFinal struct {
	Evidence rollingRenewalFinalEvidence
	Batch    RollingBatchEvidence
}

type rollingRenewalTreeBinding struct {
	BatchID        string `json:"batchId"`
	CommitmentTxid string `json:"commitmentTxid"`
	TreeDigest     string `json:"treeDigest"`
}

// Bind the exact tree session independently of signatures added during MuSig
// completion. Node metadata, topology, transaction headers and all outputs
// remain covered by this digest.
func rollingTreeBinding(e rollingRenewalFinalEvidence) (rollingRenewalTreeBinding, error) {
	commitment, err := parseCanonicalVaultBoardPSBT(e.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil {
		return rollingRenewalTreeBinding{}, err
	}
	flat, _, err := canonicalLightRenewalTree(e.VtxoTree)
	if err != nil {
		return rollingRenewalTreeBinding{}, err
	}
	for i := range flat {
		p, err := parseCanonicalVaultBoardPSBT(flat[i].Tx, maxVaultBoardProofBytes)
		if err != nil {
			return rollingRenewalTreeBinding{}, err
		}
		p.Inputs[0].TaprootKeySpendSig = nil
		flat[i].Tx, err = p.B64Encode()
		if err != nil {
			return rollingRenewalTreeBinding{}, err
		}
	}
	raw, err := json.Marshal(struct {
		BatchID     string             `json:"batchId"`
		BatchExpiry uint32             `json:"batchExpiry"`
		Commitment  string             `json:"commitment"`
		Tree        arktree.FlatTxTree `json:"tree"`
	}{e.BatchID, e.BatchExpiry, commitment.UnsignedTx.TxHash().String(), flat})
	if err != nil {
		return rollingRenewalTreeBinding{}, err
	}
	digest := sha256.Sum256(append([]byte(rolling.RollingProgram+"\x00renewal-tree\x00"), raw...))
	return rollingRenewalTreeBinding{BatchID: e.BatchID, CommitmentTxid: commitment.UnsignedTx.TxHash().String(), TreeDigest: hex.EncodeToString(digest[:])}, nil
}

func verifyRollingRetainedBatch(c *rolling.Contract, record policy.RollingSnapshot, batch RollingBatchEvidence) error {
	retained, ok := record.Events["final_authorized"]
	if _, signed := record.Events["final_signed"]; !ok || !signed {
		return fmt.Errorf("rolling finalized batch lacks retained final signatures")
	}
	var evidence rollingRenewalFinalEvidence
	if err := json.Unmarshal([]byte(retained.Evidence), &evidence); err != nil {
		return err
	}
	verified, err := verifyRollingRenewalFinal(c, record, evidence)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(verified.Evidence)
	if err != nil || string(canonical) != retained.Evidence || verified.Batch != batch {
		return fmt.Errorf("rolling finalized batch differs from retained recovery")
	}
	return nil
}

func verifyRollingRenewalFinal(c *rolling.Contract, record policy.RollingSnapshot, e rollingRenewalFinalEvidence) (verifiedRollingRenewalFinal, error) {
	return verifyRollingRenewalFinalStage(c, record, e, true)
}

// The unsigned stage retains every recovery, source and destination check; it
// permits no forfeit signatures before asking the pinned emulator to approve.
func verifyRollingRenewalFinalStage(c *rolling.Contract, record policy.RollingSnapshot, e rollingRenewalFinalEvidence, emulatorSigned bool) (verifiedRollingRenewalFinal, error) {
	fail := func(err error) (verifiedRollingRenewalFinal, error) { return verifiedRollingRenewalFinal{}, err }
	created, err := time.Parse(time.RFC3339, record.Operation.CreatedAt)
	if err != nil || record.Operation.Proposal.Kind != rolling.RenewalOperation || len(e.BatchID) == 0 || len(e.BatchID) > 256 {
		return fail(fmt.Errorf("rolling renewal final identity"))
	}
	if _, err = record.Operation.Proposal.Rebuild(c, created.Unix()); err != nil {
		return fail(err)
	}
	pins, err := deployment.IdentityFor(record.Enrollment.Network)
	if err != nil || e.BatchExpiry != pins.VtxoTreeExpirySeconds {
		return fail(fmt.Errorf("rolling renewal batch expiry"))
	}
	commitment, err := parseCanonicalVaultBoardPSBT(e.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || commitment.UnsignedTx.Version != 2 || commitment.UnsignedTx.LockTime != 0 || len(commitment.UnsignedTx.TxOut) < 2 {
		return fail(fmt.Errorf("rolling renewal commitment"))
	}
	flat, vtxos, err := canonicalLightRenewalTree(e.VtxoTree)
	if err != nil {
		return fail(err)
	}
	if err = verifyRollingRecoveryHeaders(vtxos); err != nil {
		return fail(err)
	}
	binding, err := rollingTreeBinding(e)
	if err != nil {
		return fail(err)
	}
	var requested rollingRenewalTree
	var prepared rollingPreparedTree
	var peers map[string]map[string]string
	var signed rollingSignedTree
	for _, stage := range []struct {
		phase  string
		target any
	}{
		{"tree_requested", &requested}, {"tree_prepared", &prepared},
		{"nonces_committed", &peers}, {"tree_signed", &signed},
	} {
		if err = decodeRollingTreeEvent(record, stage.phase, stage.target); err != nil {
			return fail(err)
		}
	}
	if err = verifyRollingPrepared(record, requested, prepared); err != nil {
		return fail(err)
	}
	if prepared.Binding != binding || signed.Binding != binding {
		return fail(fmt.Errorf("rolling final differs from retained tree session"))
	}
	challenges, signingRoot, err := rollingTreeChallenges(c, record, prepared, peers)
	if err != nil {
		return fail(err)
	}
	if err = verifyRollingPartials(c, binding, challenges, signingRoot, signed); err != nil {
		return fail(err)
	}
	forfeitPub, err := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	if err != nil {
		return fail(err)
	}
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: e.BatchExpiry}
	if err = arktree.ValidateVtxoTree(vtxos, commitment, forfeitPub, expiry); err != nil {
		return fail(err)
	}
	if err = verifyVaultBoardBatchOutput(vtxos, commitment, forfeitPub, expiry); err != nil {
		return fail(err)
	}
	sweep := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPub}}, Locktime: expiry}
	script, err := sweep.Script()
	if err != nil {
		return fail(err)
	}
	sweepRoot := txscript.NewBaseTapLeaf(script).TapHash()
	if err = arktree.ValidateTreeSigs(sweepRoot[:], commitment.UnsignedTx.TxOut[0].Value, vtxos); err != nil {
		return fail(fmt.Errorf("rolling renewal requires signed recovery paths: %w", err))
	}
	var receiver *wire.MsgTx
	for _, leaf := range vtxos.Leaves() {
		if record.Operation.Proposal.VerifyBatchLeaf(c, leaf.UnsignedTx, created.Unix()) != nil {
			continue
		}
		if receiver != nil {
			return fail(fmt.Errorf("rolling renewal repeated replacement"))
		}
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(leaf, 0)
		if err != nil || len(keys) != 2 || bytes.Equal(keys[0].SerializeCompressed()[1:], keys[1].SerializeCompressed()[1:]) {
			return fail(fmt.Errorf("rolling renewal tree signer count"))
		}
		if !bytes.Equal(keys[0].SerializeCompressed(), c.Parameters.DelegatePubkey) && !bytes.Equal(keys[1].SerializeCompressed(), c.Parameters.DelegatePubkey) {
			return fail(fmt.Errorf("rolling renewal delegate substitution"))
		}
		receiver = leaf.UnsignedTx
	}
	if receiver == nil {
		return fail(fmt.Errorf("rolling renewal exact replacement group missing"))
	}
	connectorFlat, connectors, err := canonicalLightRenewalTree(e.Connectors)
	if err != nil {
		return fail(err)
	}
	if err = verifyRollingRecoveryHeaders(connectors); err != nil {
		return fail(err)
	}
	if err = connectors.Validate(); err != nil {
		return fail(err)
	}
	root := connectors.Root.UnsignedTx.TxIn[0].PreviousOutPoint
	if root.Hash != commitment.UnsignedTx.TxHash() || root.Index != 1 {
		return fail(fmt.Errorf("rolling renewal connector commitment"))
	}
	var total int64
	for _, out := range connectors.Root.UnsignedTx.TxOut {
		total += out.Value
	}
	if total != commitment.UnsignedTx.TxOut[1].Value {
		return fail(fmt.Errorf("rolling renewal connector amount"))
	}
	sources := record.Operation.Proposal.Sources
	if len(e.ForfeitPSBTs) != len(sources) {
		return fail(fmt.Errorf("rolling renewal forfeit coverage"))
	}
	emu := arkade.ComputeArkadeScriptPublicKey(c.Keys.Emulator, arkade.ArkadeScriptHash(c.Programs.Renew))
	var expected [][]byte
	if emulatorSigned {
		expected = [][]byte{schnorr.SerializePubKey(emu)}
	}
	used := map[wire.OutPoint]bool{}
	for i, raw := range e.ForfeitPSBTs {
		p, err := parseCanonicalVaultBoardPSBT(raw, maxVaultBoardProofBytes)
		if err != nil || p.UnsignedTx.Version != 3 || p.UnsignedTx.LockTime != 0 || len(p.Inputs) != 2 || len(p.UnsignedTx.TxIn) != 2 || len(p.Outputs) != 2 || len(p.UnsignedTx.TxOut) != 2 || len(p.Unknowns) != 0 {
			return fail(fmt.Errorf("rolling renewal forfeit shape"))
		}
		source := sources[i]
		old := wire.OutPoint{Hash: source.Previous.TxHash(), Index: source.Index}
		if p.UnsignedTx.TxIn[0].PreviousOutPoint != old {
			return fail(fmt.Errorf("rolling renewal forfeit source order"))
		}
		funding := p.UnsignedTx.TxIn[1].PreviousOutPoint
		if used[funding] {
			return fail(fmt.Errorf("rolling renewal reused connector"))
		}
		used[funding] = true
		var connector *wire.TxOut
		for _, leaf := range connectors.Leaves() {
			if funding.Hash == leaf.UnsignedTx.TxHash() && funding.Index == 0 {
				connector = leaf.UnsignedTx.TxOut[0]
			}
		}
		value := source.Previous.TxOut[source.Index].Value
		if connector == nil || connector.Value < 330 || connector.Value > 21_000_000*100_000_000-value {
			return fail(fmt.Errorf("rolling renewal connector leaf"))
		}
		for index, want := range []*wire.TxOut{source.Previous.TxOut[source.Index], connector} {
			input := p.Inputs[index]
			if p.UnsignedTx.TxIn[index].Sequence != wire.MaxTxInSequenceNum || input.WitnessUtxo == nil || input.WitnessUtxo.Value != want.Value || !bytes.Equal(input.WitnessUtxo.PkScript, want.PkScript) || len(input.PartialSigs) != 0 || len(input.FinalScriptWitness) != 0 || len(input.FinalScriptSig) != 0 || len(input.TaprootKeySpendSig) != 0 {
				return fail(fmt.Errorf("rolling renewal forfeit input %d", index))
			}
		}
		if err = requireExactLeafWithSighash(p.Inputs[0], c.PkScript, c.Renew.Script, c.Renew.ControlBlock, expected, txscript.SigHashDefault); err != nil {
			return fail(err)
		}
		if err = requireVerifiedSignersWithSighash(p, 0, expected, c.Renew.Script, txscript.SigHashDefault); err != nil {
			return fail(err)
		}
		if len(p.Inputs[1].TaprootScriptSpendSig) != 0 || len(p.Inputs[1].TaprootLeafScript) != 0 || p.Inputs[1].SighashType != txscript.SigHashDefault {
			return fail(fmt.Errorf("rolling renewal connector must remain unsigned"))
		}
		destination := append([]byte{txscript.OP_0, 0x14}, btcutil.Hash160(forfeitPub.SerializeCompressed())...)
		anchor := txutils.AnchorOutput()
		if p.UnsignedTx.TxOut[0].Value != value+connector.Value-anchor.Value || !bytes.Equal(p.UnsignedTx.TxOut[0].PkScript, destination) || p.UnsignedTx.TxOut[1].Value != anchor.Value || !bytes.Equal(p.UnsignedTx.TxOut[1].PkScript, anchor.PkScript) {
			return fail(fmt.Errorf("rolling renewal forfeit destination or amount"))
		}
	}
	e.VtxoTree, e.Connectors = flat, connectorFlat
	var leaf bytes.Buffer
	if err = receiver.Serialize(&leaf); err != nil {
		return fail(err)
	}
	return verifiedRollingRenewalFinal{Evidence: e, Batch: RollingBatchEvidence{LeafTxHex: hex.EncodeToString(leaf.Bytes()), CommitmentTxid: commitment.UnsignedTx.TxHash().String()}}, nil
}

// The qualified stock graph is immediately executable once its commitment
// confirms. Valid signatures alone do not exclude added absolute or relative
// delays that could push recovery past the Operator's sweep window.
func verifyRollingRecoveryHeaders(graph *arktree.TxTree) error {
	if graph == nil || graph.Root == nil || graph.Root.UnsignedTx == nil {
		return fmt.Errorf("rolling recovery graph missing")
	}
	tx := graph.Root.UnsignedTx
	if tx.Version != 3 || tx.LockTime != 0 || len(tx.TxIn) != 1 || tx.TxIn[0].Sequence != wire.MaxTxInSequenceNum {
		return fmt.Errorf("rolling recovery graph has unsupported locktime or sequence")
	}
	for _, child := range graph.Children {
		if err := verifyRollingRecoveryHeaders(child); err != nil {
			return err
		}
	}
	return nil
}
