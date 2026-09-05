package application

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type vaultBoardFinalFixture struct {
	proof    vaultBoardProofFixture
	forfeit  *btcec.PublicKey
	expiry   arklib.RelativeLocktime
	register policy.VaultBoardAuthorization
	evidence vaultBoardFinalEvidence
}

func newVaultBoardFinalFixture(t *testing.T) vaultBoardFinalFixture {
	t.Helper()
	proof := newVaultBoardProofFixture(t)
	return newVaultBoardFinalFixtureFromProof(t, proof)
}

func newVaultBoardFinalFixtureFromProof(t *testing.T, proof vaultBoardProofFixture) vaultBoardFinalFixture {
	t.Helper()
	return newVaultBoardFinalFixtureForNetwork(t, proof, deployment.NetworkMutinynet)
}

func newVaultBoardFinalFixtureForNetwork(t *testing.T, proof vaultBoardProofFixture, network string) vaultBoardFinalFixture {
	t.Helper()
	id, err := deployment.IdentityFor(network)
	if err != nil {
		t.Fatal(err)
	}
	return newVaultBoardFinalFixtureForPolicy(t, proof, id.CheckpointForfeitPubHex, id.VtxoTreeExpirySeconds, false)
}

func newVaultBoardFinalFixtureForPolicy(t *testing.T, proof vaultBoardProofFixture, forfeitHex string, batchExpiry uint32, extraReceiver bool) vaultBoardFinalFixture {
	t.Helper()
	forfeitBytes, err := hex.DecodeString(forfeitHex)
	if err != nil {
		t.Fatal(err)
	}
	forfeit, err := btcec.ParsePubKey(forfeitBytes)
	if err != nil {
		t.Fatal(err)
	}
	treeSigner, _ := btcec.NewPrivateKey()
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: batchExpiry}
	leaves := []arktree.Leaf{{
		Outputs:             []arktree.LeafOutput{{Amount: uint64(proof.receiver.Value), Script: hex.EncodeToString(proof.operation.ReceiverScript)}},
		CosignersPublicKeys: []string{hex.EncodeToString(treeSigner.PubKey().SerializeCompressed())},
	}}

	if extraReceiver {
		otherSigner, _ := btcec.NewPrivateKey()
		leaves = append(leaves, arktree.Leaf{
			Outputs:             []arktree.LeafOutput{{Amount: 500, Script: hex.EncodeToString(append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x65}, 32)...))}},
			CosignersPublicKeys: []string{hex.EncodeToString(otherSigner.PubKey().SerializeCompressed())},
		})
	}

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
		[]*wire.TxOut{{Value: batchAmount, PkScript: batchScript}}, 2, 0,
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
	operationID, err := policy.ComputeVaultBoardOperationID(proof.operation.VaultID, proof.operation.Txid, proof.operation.Vout)
	if err != nil {
		t.Fatal(err)
	}
	proof.operation.OperationID = operationID
	register := policy.VaultBoardAuthorization{
		OperationID: operationID, Phase: policy.VaultBoardPhaseRegister,
		ReceiverSats: proof.receiver.Value, FeeSats: proof.operation.ValueSats - proof.receiver.Value,
	}
	return vaultBoardFinalFixture{
		proof: proof, forfeit: forfeit, expiry: expiry, register: register,
		evidence: vaultBoardFinalEvidence{
			BatchID: "round-123", BatchExpiry: expiry.Value,
			SignedCommitmentPSBT: signed, UnsignedCommitmentPSBT: unsigned,
			VtxoTree: flat, InputIndexes: []int{0},
			Recipients: []vaultBoardRecipientEvidence{{
				Script: bytes.Clone(proof.operation.ReceiverScript), AmountSats: proof.receiver.Value,
			}},
		},
	}
}

func TestVerifyVaultBoardFinalBindsCommitmentTreeAndReceiver(t *testing.T) {
	fixture := newVaultBoardFinalFixture(t)
	verified, err := verifyVaultBoardFinal(
		fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree,
		fixture.expiry, deployment.NetworkMutinynet,
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
	again, err := verifyVaultBoardFinal(
		reordered, fixture.proof.operation, fixture.register, fixture.proof.tree,
		fixture.expiry, deployment.NetworkMutinynet,
	)
	if err != nil || !bytes.Equal(again.RequestDigest, verified.RequestDigest) {
		t.Fatalf("tree order changed canonical digest: %x %v", again.RequestDigest, err)
	}
}

func TestVerifyVaultBoardFinalRejectsUnpinnedOrMutatedEvidence(t *testing.T) {
	fixture := newVaultBoardFinalFixture(t)
	tests := []struct {
		name   string
		mutate func(*vaultBoardFinalEvidence, *policy.VaultBoardAuthorization)
		want   string
	}{
		{name: "batch expiry", mutate: func(e *vaultBoardFinalEvidence, _ *policy.VaultBoardAuthorization) { e.BatchExpiry++ }, want: "batch policy"},
		{name: "receiver amount", mutate: func(e *vaultBoardFinalEvidence, _ *policy.VaultBoardAuthorization) { e.Recipients[0].AmountSats-- }, want: "receiver"},
		{name: "assets", mutate: func(e *vaultBoardFinalEvidence, _ *policy.VaultBoardAuthorization) {
			e.Recipients[0].HasAssets = true
		}, want: "receiver"},
		{name: "register amount", mutate: func(_ *vaultBoardFinalEvidence, a *policy.VaultBoardAuthorization) { a.ReceiverSats-- }, want: "receiver"},
		{name: "wrong input", mutate: func(e *vaultBoardFinalEvidence, _ *policy.VaultBoardAuthorization) { e.InputIndexes[0] = 1 }, want: "input index"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := fixture.evidence
			evidence.Recipients = append([]vaultBoardRecipientEvidence(nil), fixture.evidence.Recipients...)
			evidence.InputIndexes = append([]int(nil), fixture.evidence.InputIndexes...)
			register := fixture.register
			test.mutate(&evidence, &register)
			_, err := verifyVaultBoardFinal(
				evidence, fixture.proof.operation, register, fixture.proof.tree,
				fixture.expiry, deployment.NetworkMutinynet,
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
	if _, err := verifyVaultBoardFinal(
		fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree,
		fixture.expiry, deployment.NetworkMutinynet,
	); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("missing signature accepted: %v", err)
	}
}

func TestVerifyVaultBoardFinalRejectsCommitmentMutation(t *testing.T) {
	fixture := newVaultBoardFinalFixture(t)
	encodeBoth := func(t *testing.T, mutate func(*psbt.Packet)) vaultBoardFinalEvidence {
		t.Helper()
		evidence := fixture.evidence
		for signed, target := range map[bool]*string{false: &evidence.UnsignedCommitmentPSBT, true: &evidence.SignedCommitmentPSBT} {
			raw := fixture.evidence.UnsignedCommitmentPSBT
			if signed {
				raw = fixture.evidence.SignedCommitmentPSBT
			}
			packet, err := parsePSBT(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(packet)
			*target, err = packet.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
		}
		return evidence
	}
	tests := []struct {
		name     string
		evidence func(*testing.T) vaultBoardFinalEvidence
		want     string
	}{
		{name: "version", evidence: func(t *testing.T) vaultBoardFinalEvidence {
			return encodeBoth(t, func(packet *psbt.Packet) { packet.UnsignedTx.Version = 3 })
		}, want: "version"},
		{name: "locktime", evidence: func(t *testing.T) vaultBoardFinalEvidence {
			return encodeBoth(t, func(packet *psbt.Packet) { packet.UnsignedTx.LockTime = 1 })
		}, want: "locktime"},
		{name: "txid", evidence: func(t *testing.T) vaultBoardFinalEvidence {
			evidence := fixture.evidence
			packet, err := parsePSBT(evidence.SignedCommitmentPSBT)
			if err != nil {
				t.Fatal(err)
			}
			packet.UnsignedTx.TxOut[0].Value--
			evidence.SignedCommitmentPSBT, err = packet.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			return evidence
		}, want: "txid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifyVaultBoardFinal(
				test.evidence(t), fixture.proof.operation, fixture.register, fixture.proof.tree,
				fixture.expiry, deployment.NetworkMutinynet,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("commitment mutation accepted: %v", err)
			}
		})
	}
}

func TestVaultBoardOutpointUsesCanonicalDisplayOrder(t *testing.T) {
	display := make([]byte, chainhash.HashSize)
	for i := range display {
		display[i] = byte(i)
	}
	hash, err := chainhash.NewHashFromStr(hex.EncodeToString(display))
	if err != nil {
		t.Fatal(err)
	}
	op := policy.VaultBoardOperation{Txid: display, Vout: 7}
	if !vaultBoardOutpointMatches(op, wire.OutPoint{Hash: *hash, Index: 7}) {
		t.Fatal("canonical display-order board outpoint did not match")
	}
	var reversed chainhash.Hash
	copy(reversed[:], display)
	if vaultBoardOutpointMatches(op, wire.OutPoint{Hash: reversed, Index: 7}) {
		t.Fatal("internal-byte-order alias matched a different board outpoint")
	}
}

func TestCanonicalVaultBoardTreeRejectsDeclaredTxidDrift(t *testing.T) {
	fixture := newVaultBoardFinalFixture(t)
	fixture.evidence.VtxoTree[0].Txid = strings.Repeat("00", 32)
	if _, err := canonicalVaultBoardTree(fixture.evidence.VtxoTree); err == nil || !strings.Contains(err.Error(), "txid") {
		t.Fatalf("declared tree txid drift accepted: %v", err)
	}
}

func TestVerifyVaultBoardFinalUsesDeploymentForfeitKey(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			fixture := newVaultBoardFinalFixtureForNetwork(t, newVaultBoardProofFixture(t), network)
			if _, err := verifyVaultBoardFinal(fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree, fixture.expiry, network); err != nil {
				t.Fatal(err)
			}
			for _, other := range []string{"", "unknown", deployment.NetworkMainnet, deployment.NetworkMutinynet} {
				if other == network {
					continue
				}
				if _, err := verifyVaultBoardFinal(fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree, fixture.expiry, other); err == nil {
					t.Fatalf("accepted deployment %q for %q tree", other, network)
				}
			}
		})
	}
}

func TestVerifyVaultBoardFinalMainnetObservedBatchExpiry(t *testing.T) {
	// Observed on https://arkade.computer/v1/batch/events on 2026-09-05,
	// batch be8cd65e-6466-44d6-8691-6ea9360fa23c. Keep the fixture independent
	// of the deployment pin: the boarding recovery delay is a different policy.
	const observedExpiry uint32 = 2592256
	id, err := deployment.IdentityFor(deployment.NetworkMainnet)
	if err != nil {
		t.Fatal(err)
	}
	for _, shared := range []bool{false, true} {
		fixture := newVaultBoardFinalFixtureForPolicy(t, newVaultBoardProofFixture(t), id.CheckpointForfeitPubHex, observedExpiry, shared)
		expected := vaultBoardFinalExpiry(id.VtxoTreeExpirySeconds)
		if _, err := verifyVaultBoardFinal(fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree, expected, deployment.NetworkMainnet); err != nil {
			t.Fatalf("observed mainnet expiry, shared=%t: %v", shared, err)
		}
		fixture.evidence.BatchExpiry = 7776256
		if _, err := verifyVaultBoardFinal(fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree, expected, deployment.NetworkMainnet); err == nil || !strings.Contains(err.Error(), "expiry got=7776256 want=2592256") {
			t.Fatalf("boarding recovery delay accepted as batch expiry: %v", err)
		}
		// Matching metadata cannot disguise a Batch Output built with another
		// sweep delay, even when there are no child nodes for ark-lib to check.
		wrongTree := newVaultBoardFinalFixtureForPolicy(t, newVaultBoardProofFixture(t), id.CheckpointForfeitPubHex, 7776256, shared)
		wrongTree.evidence.BatchExpiry = observedExpiry
		if _, err := verifyVaultBoardFinal(wrongTree.evidence, wrongTree.proof.operation, wrongTree.register, wrongTree.proof.tree, expected, deployment.NetworkMainnet); err == nil || !strings.Contains(err.Error(), "VTXO tree policy") {
			t.Fatalf("mislabeled sweep delay accepted, shared=%t: %v", shared, err)
		}
	}
}

func TestVerifyVaultBoardFinalRejectsOtherNetworkForfeitAtPinnedExpiry(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			id, _ := deployment.IdentityFor(network)
			other := deployment.NetworkMainnet
			if network == other {
				other = deployment.NetworkMutinynet
			}
			otherID, _ := deployment.IdentityFor(other)
			fixture := newVaultBoardFinalFixtureForPolicy(t, newVaultBoardProofFixture(t), otherID.CheckpointForfeitPubHex, id.VtxoTreeExpirySeconds, false)
			_, err := verifyVaultBoardFinal(fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree, fixture.expiry, network)
			if err == nil || !strings.Contains(err.Error(), "VTXO tree policy") {
				t.Fatalf("wrong forfeit key: %v", err)
			}
		})
	}
}

func TestVerifyVaultBoardFinalWithOtherBatchParticipants(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			id, _ := deployment.IdentityFor(network)
			fixture := newVaultBoardFinalFixtureForPolicy(t, newVaultBoardProofFixture(t), id.CheckpointForfeitPubHex, id.VtxoTreeExpirySeconds, true)
			if len(fixture.evidence.VtxoTree) < 3 {
				t.Fatal("fixture must include child nodes")
			}
			if _, err := verifyVaultBoardFinal(fixture.evidence, fixture.proof.operation, fixture.register, fixture.proof.tree, fixture.expiry, network); err != nil {
				t.Fatal(err)
			}
		})
	}
}
