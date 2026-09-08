package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

type rollingRenewalTree struct {
	BatchID        string             `json:"batchId"`
	BatchExpiry    uint32             `json:"batchExpiry"`
	CommitmentPSBT string             `json:"commitmentPsbt"`
	VtxoTree       arktree.FlatTxTree `json:"vtxoTree"`
}

type rollingPreparedTree struct {
	Binding rollingRenewalTreeBinding   `json:"binding"`
	Tree    rollingRenewalTree          `json:"tree"`
	Capsule lightDelegationNonceCapsule `json:"capsule"`
}

type rollingSignedTree struct {
	Binding    rollingRenewalTreeBinding `json:"binding"`
	Signatures map[string]string         `json:"signatures"`
}

func (e rollingRenewalTree) finalEvidence() rollingRenewalFinalEvidence {
	return rollingRenewalFinalEvidence{BatchID: e.BatchID, BatchExpiry: e.BatchExpiry, CommitmentPSBT: e.CommitmentPSBT, VtxoTree: e.VtxoTree}
}

// The same complete output group that final signing requires is checked before
// generating any nonce. Compressed delegate parity belongs to the descriptor.
func verifyRollingSigningTree(c *rolling.Contract, record policy.RollingSnapshot, e rollingRenewalTree) (*arktree.TxTree, *psbt.Packet, []byte, error) {
	fail := func(err error) (*arktree.TxTree, *psbt.Packet, []byte, error) { return nil, nil, nil, err }
	created, err := time.Parse(time.RFC3339, record.Operation.CreatedAt)
	if err != nil || record.Operation.Proposal.Kind != rolling.RenewalOperation {
		return fail(fmt.Errorf("rolling tree requires renewal"))
	}
	if _, err = record.Operation.Proposal.Rebuild(c, created.Unix()); err != nil {
		return fail(err)
	}
	pins, err := deployment.IdentityFor(record.Enrollment.Network)
	if err != nil || e.BatchExpiry != pins.VtxoTreeExpirySeconds || len(e.BatchID) == 0 || len(e.BatchID) > 256 {
		return fail(fmt.Errorf("rolling tree batch binding"))
	}
	commitment, err := parseCanonicalVaultBoardPSBT(e.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || commitment.UnsignedTx.Version != 2 || commitment.UnsignedTx.LockTime != 0 || len(commitment.UnsignedTx.TxOut) < 2 {
		return fail(fmt.Errorf("rolling tree commitment"))
	}
	_, graph, err := canonicalLightRenewalTree(e.VtxoTree)
	if err != nil {
		return fail(err)
	}
	if err = verifyRollingRecoveryHeaders(graph); err != nil {
		return fail(err)
	}
	forfeit, err := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	if err != nil {
		return fail(err)
	}
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: e.BatchExpiry}
	if err = arktree.ValidateVtxoTree(graph, commitment, forfeit, expiry); err != nil {
		return fail(err)
	}
	if err = verifyVaultBoardBatchOutput(graph, commitment, forfeit, expiry); err != nil {
		return fail(err)
	}
	matched := false
	for _, leaf := range graph.Leaves() {
		if record.Operation.Proposal.VerifyBatchLeaf(c, leaf.UnsignedTx, created.Unix()) != nil {
			continue
		}
		if matched {
			return fail(fmt.Errorf("rolling tree duplicate replacement group"))
		}
		matched = true
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(leaf, 0)
		if err != nil || len(keys) != 2 || bytes.Equal(schnorr.SerializePubKey(keys[0]), schnorr.SerializePubKey(keys[1])) {
			return fail(fmt.Errorf("rolling tree signer count"))
		}
		if !bytes.Equal(keys[0].SerializeCompressed(), c.Parameters.DelegatePubkey) && !bytes.Equal(keys[1].SerializeCompressed(), c.Parameters.DelegatePubkey) {
			return fail(fmt.Errorf("rolling tree delegate substitution"))
		}
	}
	if !matched {
		return fail(fmt.Errorf("rolling tree exact replacement group missing"))
	}
	sweep := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeit}}, Locktime: expiry}
	script, err := sweep.Script()
	if err != nil {
		return fail(err)
	}
	root := txscript.NewBaseTapLeaf(script).TapHash()
	return graph, commitment, root[:], nil
}

// A nonce capsule commits the vault, full immutable enrollment, operation and
// tree. The envelope and nonce primitives are shared with the existing delegate;
// the separate rolling delegate scalar and binding domain isolate their keys.
func rollingNonceBinding(record policy.RollingSnapshot, tree rollingRenewalTree) (string, error) {
	raw, err := json.Marshal(struct {
		Enrollment policy.RollingEnrollment
		Operation  policy.RollingOperation
		Tree       rollingRenewalTree
	}{record.Enrollment, record.Operation, tree})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(rolling.RollingProgram+"\x00renewal-nonces-v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func decodeRollingTreeEvent(record policy.RollingSnapshot, phase string, target any) error {
	event, ok := record.Events[phase]
	if !ok || json.Unmarshal([]byte(event.Evidence), target) != nil {
		return fmt.Errorf("rolling %s transcript missing", phase)
	}
	raw, err := json.Marshal(target)
	if err != nil || string(raw) != event.Evidence {
		return fmt.Errorf("rolling %s transcript not canonical", phase)
	}
	return nil
}

func rollingTreeAuthority(record policy.RollingSnapshot, now int64) error {
	if record.Operation.Proposal.Kind != rolling.RenewalOperation {
		return fmt.Errorf("rolling tree operation kind")
	}
	for _, phase := range []string{"cleanup_pending", "aborted", "final_authorized", "submitted", "finalized"} {
		if _, ok := record.Events[phase]; ok {
			return fmt.Errorf("rolling tree session ended")
		}
	}
	if _, ok := record.Events["registered"]; !ok {
		return fmt.Errorf("rolling tree registration missing")
	}
	return rolling.CheckRenewalTime(record.Operation.Proposal.Message, now)
}

func (k *fileBackedVaultKeys) withRollingDelegate(ctx context.Context, record policy.RollingSnapshot, c *rolling.Contract, run func(*btcec.PrivateKey) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return k.withMaster(func(master *btcec.PrivateKey) error {
		key, err := deriveRollingDelegateKey(master, rollingKeyContext{vault: record.Enrollment.VaultID, network: record.Enrollment.Network, operator: c.Keys.Operator.SerializeCompressed()})
		if err != nil {
			return err
		}
		defer key.Key.Zero()
		if !bytes.Equal(key.PubKey().SerializeCompressed(), c.Parameters.DelegatePubkey) {
			return fmt.Errorf("rolling delegate scope mismatch")
		}
		return run(key)
	})
}

// Only a retained semantic operation is accepted by the key backend. The
// service must commit this capsule before exposing its public nonces.
func (k *fileBackedVaultKeys) prepareRollingTree(ctx context.Context, vault, id string) (rollingPreparedTree, error) {
	record, c, store, err := k.rollingKeyOperation(ctx, vault, id)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	if err = rollingTreeAuthority(record, store.NowUTC().Unix()); err != nil {
		return rollingPreparedTree{}, err
	}
	var tree rollingRenewalTree
	if err = decodeRollingTreeEvent(record, "tree_requested", &tree); err != nil {
		return rollingPreparedTree{}, err
	}
	graph, _, _, err := verifyRollingSigningTree(c, record, tree)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	if _, ok := record.Events["tree_prepared"]; ok {
		var prior rollingPreparedTree
		err = decodeRollingTreeEvent(record, "tree_prepared", &prior)
		if err == nil {
			err = verifyRollingPrepared(record, tree, prior)
		}
		return prior, err
	}
	bound, err := rollingTreeBinding(tree.finalEvidence())
	if err != nil {
		return rollingPreparedTree{}, err
	}
	binding, err := rollingNonceBinding(record, tree)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	result := rollingPreparedTree{Binding: bound, Tree: tree}
	err = k.withRollingDelegate(ctx, record, c, func(key *btcec.PrivateKey) error {
		seed := make([]byte, 32)
		defer zeroServiceBytes(seed)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		aead, err := delegationNonceAEAD(key)
		if err != nil {
			return err
		}
		iv := make([]byte, aead.NonceSize())
		if _, err = rand.Read(iv); err != nil {
			return err
		}
		nodes, err := delegationSigningNodes(graph, key.PubKey())
		if err != nil || len(nodes) == 0 {
			return fmt.Errorf("rolling signing nodes missing")
		}
		nonces := map[string]string{}
		for txid := range nodes {
			nonce, err := delegationNodeNonces(key, seed, binding, txid)
			if err != nil {
				return err
			}
			nonces[txid] = hex.EncodeToString(nonce.PubNonce[:])
			zeroServiceBytes(nonce.SecNonce[:])
		}
		result.Capsule = lightDelegationNonceCapsule{Binding: binding, Nonces: nonces, IV: hex.EncodeToString(iv), Ciphertext: hex.EncodeToString(aead.Seal(nil, iv, seed, []byte(binding)))}
		return nil
	})
	return result, err
}

func verifyRollingPrepared(record policy.RollingSnapshot, tree rollingRenewalTree, prepared rollingPreparedTree) error {
	binding, err := rollingTreeBinding(tree.finalEvidence())
	if err != nil {
		return err
	}
	nonceBinding, err := rollingNonceBinding(record, tree)
	if err != nil || prepared.Binding != binding || prepared.Capsule.Binding != nonceBinding || !sameDelegationBytes(tree, prepared.Tree) {
		return fmt.Errorf("rolling prepared tree binding")
	}
	// Validate the public envelope before retaining or releasing it. The
	// private backend authenticates the ciphertext again when it opens the seed.
	iv, ivErr := hex.DecodeString(prepared.Capsule.IV)
	ciphertext, cipherErr := hex.DecodeString(prepared.Capsule.Ciphertext)
	if ivErr != nil || cipherErr != nil || len(iv) != 12 || len(ciphertext) != 32+16 {
		return fmt.Errorf("rolling prepared nonce envelope shape")
	}
	c, err := rolling.DecodeDescriptor([]byte(record.Enrollment.Descriptor))
	if err != nil {
		return err
	}
	pub, err := btcec.ParsePubKey(c.Parameters.DelegatePubkey)
	if err != nil {
		return err
	}
	_, graph, err := canonicalLightRenewalTree(tree.VtxoTree)
	if err != nil {
		return err
	}
	nodes, err := delegationSigningNodes(graph, pub)
	if err != nil || len(nodes) == 0 || len(nodes) != len(prepared.Capsule.Nonces) {
		return fmt.Errorf("rolling prepared nonce coverage")
	}
	for txid := range nodes {
		raw, err := hex.DecodeString(prepared.Capsule.Nonces[txid])
		if err != nil || len(raw) != 66 {
			return fmt.Errorf("rolling prepared nonce encoding")
		}
		if _, err = btcec.ParsePubKey(raw[:33]); err != nil {
			return err
		}
		if _, err = btcec.ParsePubKey(raw[33:]); err != nil {
			return err
		}
	}
	return nil
}

type rollingNodeChallenge struct {
	Own       [66]byte
	Aggregate [66]byte
	Keys      []*btcec.PublicKey
	Digest    [32]byte
}

func rollingTreeChallenges(c *rolling.Contract, record policy.RollingSnapshot, prepared rollingPreparedTree, all map[string]map[string]string) (map[string]rollingNodeChallenge, []byte, error) {
	graph, commitment, root, err := verifyRollingSigningTree(c, record, prepared.Tree)
	if err != nil {
		return nil, nil, err
	}
	pub, err := btcec.ParsePubKey(c.Parameters.DelegatePubkey)
	if err != nil {
		return nil, nil, err
	}
	nodes, err := delegationSigningNodes(graph, pub)
	if err != nil || len(nodes) == 0 || len(nodes) != len(all) || len(nodes) != len(prepared.Capsule.Nonces) {
		return nil, nil, fmt.Errorf("rolling nonce node coverage")
	}
	result := map[string]rollingNodeChallenge{}
	for txid, packet := range nodes {
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(packet, 0)
		nonces := all[txid]
		if err != nil || len(keys) != len(nonces) {
			return nil, nil, fmt.Errorf("rolling nonce participant coverage")
		}
		own := hex.EncodeToString(schnorr.SerializePubKey(pub))
		if nonces[own] != prepared.Capsule.Nonces[txid] {
			return nil, nil, fmt.Errorf("rolling own nonce changed")
		}
		public := make([][66]byte, 0, len(keys))
		seen := map[string]bool{}
		var ownNonce [66]byte
		for _, key := range keys {
			name := hex.EncodeToString(schnorr.SerializePubKey(key))
			raw, err := hex.DecodeString(nonces[name])
			if err != nil || len(raw) != 66 || seen[name] {
				return nil, nil, fmt.Errorf("rolling peer nonce encoding or duplicate key")
			}
			// The stock coordinator supplies two ordinary compressed points.
			// Refuse infinity encodings before consuming this durable session.
			if _, err = btcec.ParsePubKey(raw[:33]); err != nil {
				return nil, nil, fmt.Errorf("rolling peer nonce first point: %w", err)
			}
			if _, err = btcec.ParsePubKey(raw[33:]); err != nil {
				return nil, nil, fmt.Errorf("rolling peer nonce second point: %w", err)
			}
			seen[name] = true
			public = append(public, [66]byte(raw))
			if name == own {
				ownNonce = [66]byte(raw)
			}
		}
		aggregate, err := musig2.AggregateNonces(public)
		if err != nil {
			return nil, nil, err
		}
		previous := packet.UnsignedTx.TxIn[0].PreviousOutPoint
		prevout := commitment.UnsignedTx.TxOut[0]
		if previous.Hash != commitment.UnsignedTx.TxHash() {
			parent := graph.Find(previous.Hash.String())
			if parent == nil || int(previous.Index) >= len(parent.Root.UnsignedTx.TxOut) {
				return nil, nil, fmt.Errorf("rolling signing parent")
			}
			prevout = parent.Root.UnsignedTx.TxOut[previous.Index]
		} else if previous.Index != 0 {
			return nil, nil, fmt.Errorf("rolling signing commitment output")
		}
		fetcher := txscript.NewCannedPrevOutputFetcher(prevout.PkScript, prevout.Value)
		digest, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(packet.UnsignedTx, fetcher), txscript.SigHashDefault, packet.UnsignedTx, 0, fetcher)
		if err != nil {
			return nil, nil, err
		}
		result[txid] = rollingNodeChallenge{Own: ownNonce, Aggregate: aggregate, Keys: keys, Digest: [32]byte(digest)}
	}
	return result, root, nil
}

func (k *fileBackedVaultKeys) signRollingTree(ctx context.Context, vault, id string) (rollingSignedTree, error) {
	record, c, store, err := k.rollingKeyOperation(ctx, vault, id)
	if err != nil {
		return rollingSignedTree{}, err
	}
	// Retained partials are safe to replay without reopening a nonce seed, even
	// after expiry. Cleanup still excludes sending them into a later session.
	if _, cleanup := record.Events["cleanup_pending"]; cleanup {
		return rollingSignedTree{}, fmt.Errorf("rolling tree cleanup fence")
	}
	var tree rollingRenewalTree
	var prepared rollingPreparedTree
	var peers map[string]map[string]string
	if err = decodeRollingTreeEvent(record, "tree_requested", &tree); err != nil {
		return rollingSignedTree{}, err
	}
	if err = decodeRollingTreeEvent(record, "tree_prepared", &prepared); err != nil {
		return rollingSignedTree{}, err
	}
	if err = decodeRollingTreeEvent(record, "nonces_committed", &peers); err != nil {
		return rollingSignedTree{}, err
	}
	if err = verifyRollingPrepared(record, tree, prepared); err != nil {
		return rollingSignedTree{}, err
	}
	challenges, root, err := rollingTreeChallenges(c, record, prepared, peers)
	if err != nil {
		return rollingSignedTree{}, err
	}
	if _, ok := record.Events["tree_signed"]; ok {
		var prior rollingSignedTree
		err = decodeRollingTreeEvent(record, "tree_signed", &prior)
		if err == nil {
			err = verifyRollingPartials(c, prepared.Binding, challenges, root, prior)
		}
		return prior, err
	}
	if err = rollingTreeAuthority(record, store.NowUTC().Unix()); err != nil {
		return rollingSignedTree{}, err
	}
	result := rollingSignedTree{Binding: prepared.Binding, Signatures: map[string]string{}}
	err = k.withRollingDelegate(ctx, record, c, func(key *btcec.PrivateKey) error {
		aead, err := delegationNonceAEAD(key)
		if err != nil {
			return err
		}
		iv, err := hex.DecodeString(prepared.Capsule.IV)
		if err != nil || len(iv) != aead.NonceSize() {
			return fmt.Errorf("rolling nonce IV")
		}
		encrypted, err := hex.DecodeString(prepared.Capsule.Ciphertext)
		if err != nil {
			return err
		}
		seed, err := aead.Open(nil, iv, encrypted, []byte(prepared.Capsule.Binding))
		if err != nil {
			return err
		}
		defer zeroServiceBytes(seed)
		if len(seed) != 32 {
			return fmt.Errorf("rolling nonce seed size")
		}
		for txid, challenge := range challenges {
			if err := ctx.Err(); err != nil {
				return err
			}
			nonce, err := delegationNodeNonces(key, seed, prepared.Capsule.Binding, txid)
			if err != nil {
				return err
			}
			defer zeroServiceBytes(nonce.SecNonce[:])
			if nonce.PubNonce != challenge.Own {
				return fmt.Errorf("rolling retained nonce differs from seed")
			}
			sig, err := musig2.Sign(nonce.SecNonce, key, challenge.Aggregate, challenge.Keys, challenge.Digest, musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(root))
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err = sig.Encode(&buf); err != nil {
				return err
			}
			result.Signatures[txid] = hex.EncodeToString(buf.Bytes())
		}
		return nil
	})
	return result, err
}

func verifyRollingPartials(c *rolling.Contract, binding rollingRenewalTreeBinding, challenges map[string]rollingNodeChallenge, root []byte, signed rollingSignedTree) error {
	if signed.Binding != binding || len(signed.Signatures) != len(challenges) {
		return fmt.Errorf("rolling partial signature coverage")
	}
	pub, err := btcec.ParsePubKey(c.Parameters.DelegatePubkey)
	if err != nil {
		return err
	}
	for txid, challenge := range challenges {
		raw, err := hex.DecodeString(signed.Signatures[txid])
		var sig musig2.PartialSignature
		if err != nil || len(raw) != 32 || sig.Decode(bytes.NewReader(raw)) != nil || !sig.Verify(challenge.Own, challenge.Aggregate, challenge.Keys, pub, challenge.Digest, musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(root)) {
			return fmt.Errorf("rolling invalid partial signature")
		}
	}
	return nil
}

func (s *Service) prepareRollingRenewalTree(ctx context.Context, manager *RollingOperations, id string, tree rollingRenewalTree) (rollingPreparedTree, error) {
	if manager == nil || isNilInterface(s.keys.rollingOperation) {
		return rollingPreparedTree{}, fmt.Errorf("rolling tree dependencies required")
	}
	record, err := manager.operation(ctx, id)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	if _, _, _, err = verifyRollingSigningTree(manager.contract, record, tree); err != nil {
		return rollingPreparedTree{}, err
	}
	flat, _, err := canonicalLightRenewalTree(tree.VtxoTree)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	tree.VtxoTree = flat
	raw, err := json.Marshal(tree)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	if _, err = manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "tree_requested", Evidence: string(raw)}); err != nil {
		return rollingPreparedTree{}, err
	}
	prepared, err := s.keys.rollingOperation.prepareRollingTree(ctx, manager.vault, id)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	if err = verifyRollingPrepared(record, tree, prepared); err != nil {
		return rollingPreparedTree{}, err
	}
	raw, err = json.Marshal(prepared)
	if err != nil {
		return rollingPreparedTree{}, err
	}
	if _, err = manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "tree_prepared", Evidence: string(raw)}); err != nil {
		return rollingPreparedTree{}, err
	}
	return prepared, nil
}

func (s *Service) signRollingRenewalTree(ctx context.Context, manager *RollingOperations, id string, peers map[string]map[string]string) (rollingSignedTree, error) {
	if manager == nil || isNilInterface(s.keys.rollingOperation) {
		return rollingSignedTree{}, fmt.Errorf("rolling tree dependencies required")
	}
	record, err := manager.operation(ctx, id)
	if err != nil {
		return rollingSignedTree{}, err
	}
	var tree rollingRenewalTree
	var prepared rollingPreparedTree
	if err = decodeRollingTreeEvent(record, "tree_requested", &tree); err != nil {
		return rollingSignedTree{}, err
	}
	if err = decodeRollingTreeEvent(record, "tree_prepared", &prepared); err != nil {
		return rollingSignedTree{}, err
	}
	if err = verifyRollingPrepared(record, tree, prepared); err != nil {
		return rollingSignedTree{}, err
	}
	challenges, root, err := rollingTreeChallenges(manager.contract, record, prepared, peers)
	if err != nil {
		return rollingSignedTree{}, err
	}
	raw, err := json.Marshal(peers)
	if err != nil {
		return rollingSignedTree{}, err
	}
	if _, err = manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "nonces_committed", Evidence: string(raw)}); err != nil {
		return rollingSignedTree{}, err
	}
	signed, err := s.keys.rollingOperation.signRollingTree(ctx, manager.vault, id)
	if err != nil {
		return rollingSignedTree{}, err
	}
	if err = verifyRollingPartials(manager.contract, prepared.Binding, challenges, root, signed); err != nil {
		return rollingSignedTree{}, err
	}
	raw, err = json.Marshal(signed)
	if err != nil {
		return rollingSignedTree{}, err
	}
	if _, err = manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "tree_signed", Evidence: string(raw)}); err != nil {
		return rollingSignedTree{}, err
	}
	return signed, nil
}
