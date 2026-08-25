package application

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type vaultBoardV2FinalFixture struct {
	proof    vaultBoardV2ProofFixture
	forfeit  *btcec.PublicKey
	expiry   arklib.RelativeLocktime
	register policy.VaultBoardV2Authorization
	evidence vaultBoardV2FinalEvidence
}

func newVaultBoardV2FinalFixture(t *testing.T) vaultBoardV2FinalFixture {
	t.Helper()
	proof := newVaultBoardV2ProofFixture(t)
	return newVaultBoardV2FinalFixtureFromProof(t, proof)
}

func newVaultBoardV2FinalFixtureFromProof(t *testing.T, proof vaultBoardV2ProofFixture) vaultBoardV2FinalFixture {
	t.Helper()
	forfeitBytes, err := hex.DecodeString(deployment.MutinynetCheckpointForfeitPubHex)
	if err != nil {
		t.Fatal(err)
	}
	forfeit, err := btcec.ParsePubKey(forfeitBytes)
	if err != nil {
		t.Fatal(err)
	}
	treeSigner, _ := btcec.NewPrivateKey()
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604_672}
	leaves := []arktree.Leaf{{
		Outputs:             []arktree.LeafOutput{{Amount: uint64(proof.receiver.Value), Script: hex.EncodeToString(proof.operation.ReceiverScript)}},
		CosignersPublicKeys: []string{hex.EncodeToString(treeSigner.PubKey().SerializeCompressed())},
	}}

	sweep := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeit}},
		Locktime:        expiry,
	}
	sweepScript, err := sweep.Script()
	if err != nil {
		t.Fatal(err)
	}
	sweepTree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript))
	sweepRoot := sweepTree.RootNode.TapHash()
	batchScript, batchAmount, err := arktree.BuildBatchOutput(leaves, sweepRoot[:])
	if err != nil {
		t.Fatal(err)
	}
	boardHash, err := chainhash.NewHashFromStr(hex.EncodeToString(proof.operation.Txid))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := psbt.New(
		[]*wire.OutPoint{{Hash: *boardHash, Index: proof.operation.Vout}},
		[]*wire.TxOut{{Value: batchAmount, PkScript: batchScript}}, 3, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	if err != nil {
		t.Fatal(err)
	}
	commitment.Inputs[0].WitnessUtxo = &wire.TxOut{Value: proof.operation.ValueSats, PkScript: bytes.Clone(proof.tree.PkScript)}
	commitment.Inputs[0].SighashType = txscript.SigHashDefault
	commitment.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: bytes.Clone(proof.tree.ControlBlock), Script: bytes.Clone(proof.tree.Collaborative),
		LeafVersion: txscript.BaseLeafVersion,
	}}
	unsigned, err := commitment.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signTapLeafAtWithSighash(commitment, 0, proof.boarding, proof.tree.Collaborative, txscript.SigHashDefault)
	if err != nil {
		t.Fatal(err)
	}
	commitment.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	signed, err := commitment.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	vtxoTree, err := arktree.BuildVtxoTree(
		&wire.OutPoint{Hash: commitment.UnsignedTx.TxHash(), Index: 0}, leaves,
		sweepRoot[:], expiry,
	)
	if err != nil {
		t.Fatal(err)
	}
	flat, err := vtxoTree.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := policy.ComputeVaultBoardV2OperationID(proof.operation.VaultID, proof.operation.Txid, proof.operation.Vout)
	if err != nil {
		t.Fatal(err)
	}
	proof.operation.OperationID = operationID
	register := policy.VaultBoardV2Authorization{
		OperationID: operationID, Phase: policy.VaultBoardV2PhaseRegister,
		ReceiverSats: proof.receiver.Value, FeeSats: proof.operation.ValueSats - proof.receiver.Value,
	}
	return vaultBoardV2FinalFixture{
		proof: proof, forfeit: forfeit, expiry: expiry, register: register,
		evidence: vaultBoardV2FinalEvidence{
			BatchID: "round-123", BatchExpiry: expiry.Value,
			SignedCommitmentPSBT: signed, UnsignedCommitmentPSBT: unsigned,
			VtxoTree: flat, InputIndexes: []int{0},
			Recipients: []vaultBoardV2RecipientEvidence{{
				Script: bytes.Clone(proof.operation.ReceiverScript), AmountSats: proof.receiver.Value,
			}},
		},
	}
}

func TestVerifyVaultBoardV2FinalBindsCommitmentTreeAndReceiver(t *testing.T) {
	fixture := newVaultBoardV2FinalFixture(t)
	verified, err := verifyVaultBoardV2Final(
		fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree,
		fixture.expiry,
	)
	if err != nil {
		t.Fatal(err)
	}
	if requireTxid(verified.CommitmentTxid) != nil || requireTxid(verified.ReceiverTxid) != nil ||
		verified.ReceiverVout != 0 || verified.InputIndex != 0 || len(verified.RequestDigest) != 32 {
		t.Fatalf("verified final = %+v", verified)
	}

	reordered := fixture.evidence
	for i, j := 0, len(reordered.VtxoTree)-1; i < j; i, j = i+1, j-1 {
		reordered.VtxoTree[i], reordered.VtxoTree[j] = reordered.VtxoTree[j], reordered.VtxoTree[i]
	}
	again, err := verifyVaultBoardV2Final(
		reordered, fixture.proof.operation, fixture.register, fixture.proof.tree,
		fixture.expiry,
	)
	if err != nil || !bytes.Equal(again.RequestDigest, verified.RequestDigest) {
		t.Fatalf("tree order changed canonical digest: %x %v", again.RequestDigest, err)
	}
}

func TestVerifyVaultBoardV2FinalRejectsUnpinnedOrMutatedEvidence(t *testing.T) {
	fixture := newVaultBoardV2FinalFixture(t)
	tests := []struct {
		name   string
		mutate func(*vaultBoardV2FinalEvidence, *policy.VaultBoardV2Authorization)
		want   string
	}{
		{name: "batch expiry", mutate: func(e *vaultBoardV2FinalEvidence, _ *policy.VaultBoardV2Authorization) { e.BatchExpiry++ }, want: "batch policy"},
		{name: "receiver amount", mutate: func(e *vaultBoardV2FinalEvidence, _ *policy.VaultBoardV2Authorization) { e.Recipients[0].AmountSats-- }, want: "receiver"},
		{name: "assets", mutate: func(e *vaultBoardV2FinalEvidence, _ *policy.VaultBoardV2Authorization) {
			e.Recipients[0].HasAssets = true
		}, want: "receiver"},
		{name: "register amount", mutate: func(_ *vaultBoardV2FinalEvidence, a *policy.VaultBoardV2Authorization) { a.ReceiverSats-- }, want: "receiver"},
		{name: "wrong input", mutate: func(e *vaultBoardV2FinalEvidence, _ *policy.VaultBoardV2Authorization) { e.InputIndexes[0] = 1 }, want: "input index"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := fixture.evidence
			evidence.Recipients = append([]vaultBoardV2RecipientEvidence(nil), fixture.evidence.Recipients...)
			evidence.InputIndexes = append([]int(nil), fixture.evidence.InputIndexes...)
			register := fixture.register
			test.mutate(&evidence, &register)
			_, err := verifyVaultBoardV2Final(
				evidence, fixture.proof.operation, register, fixture.proof.tree,
				fixture.expiry,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}

	packet, err := parsePSBT(fixture.evidence.SignedCommitmentPSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootScriptSpendSig = nil
	fixture.evidence.SignedCommitmentPSBT, _ = packet.B64Encode()
	if _, err := verifyVaultBoardV2Final(
		fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree,
		fixture.expiry,
	); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("missing signature accepted: %v", err)
	}
}

func TestVaultBoardV2OutpointUsesCanonicalDisplayOrder(t *testing.T) {
	display := make([]byte, chainhash.HashSize)
	for i := range display {
		display[i] = byte(i)
	}
	hash, err := chainhash.NewHashFromStr(hex.EncodeToString(display))
	if err != nil {
		t.Fatal(err)
	}
	op := policy.VaultBoardV2Operation{Txid: display, Vout: 7}
	if !vaultBoardV2OutpointMatches(op, wire.OutPoint{Hash: *hash, Index: 7}) {
		t.Fatal("canonical display-order board outpoint did not match")
	}
	var reversed chainhash.Hash
	copy(reversed[:], display)
	if vaultBoardV2OutpointMatches(op, wire.OutPoint{Hash: reversed, Index: 7}) {
		t.Fatal("internal-byte-order alias matched a different board outpoint")
	}
}

func TestCanonicalVaultBoardV2TreeRejectsDeclaredTxidDrift(t *testing.T) {
	fixture := newVaultBoardV2FinalFixture(t)
	fixture.evidence.VtxoTree[0].Txid = strings.Repeat("00", 32)
	if _, err := canonicalVaultBoardV2Tree(fixture.evidence.VtxoTree); err == nil || !strings.Contains(err.Error(), "txid") {
		t.Fatalf("declared tree txid drift accepted: %v", err)
	}
}
