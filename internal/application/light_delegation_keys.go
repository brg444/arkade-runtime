package application

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"golang.org/x/crypto/hkdf"
)

const delegatedOwnerSighash = txscript.SigHashAll | txscript.SigHashAnyOneCanPay

type lightDelegationTree struct {
	BatchID        string             `json:"batchId"`
	BatchExpiry    uint32             `json:"batchExpiry"`
	CommitmentPSBT string             `json:"commitmentPsbt"`
	VtxoTree       arktree.FlatTxTree `json:"vtxoTree"`
}
type lightDelegationNonceCapsule struct {
	Binding    string            `json:"binding"`
	Nonces     map[string]string `json:"nonces"`
	IV         string            `json:"iv"`
	Ciphertext string            `json:"ciphertext"`
}
type lightDelegationPreparedTree struct {
	Tree    lightDelegationTree         `json:"tree"`
	Capsule lightDelegationNonceCapsule `json:"capsule"`
}
type lightDelegationFinal struct {
	Evidence      lightRenewalFinalEvidence `json:"evidence"`
	SignedForfeit string                    `json:"signedForfeit"`
}
type lightDelegationAuthorizer interface {
	authorizeLightDelegationDelete(context.Context, light.Descriptor, lightDelegationPlan) (string, error)
	authorizeLightDelegation(context.Context, light.Descriptor, lightDelegationPlan, *lightRenewalFinalEvidence) (string, error)
	prepareLightDelegationTree(context.Context, light.Descriptor, lightDelegationPlan, lightDelegationTree) (lightDelegationNonceCapsule, error)
	signLightDelegationTree(context.Context, light.Descriptor, lightDelegationPlan, lightDelegationPreparedTree, map[string]map[string]string) (map[string]string, error)
}

func (k *fileBackedVaultKeys) withDelegationKey(ctx context.Context, d light.Descriptor, run func(*btcec.PrivateKey) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := light.ValidateDescriptor(d); err != nil {
		return err
	}
	pins, err := deployment.IdentityFor(d.Network)
	if err != nil {
		return err
	}
	scope, err := newVtxoKeyContext(d.VaultID, d.Network, mustDecodeRenewalHex(pins.OperatorSignerPubHex))
	if err != nil {
		return err
	}
	scope.lightProfile = true
	return k.withMaster(func(master *btcec.PrivateKey) error {
		key, err := deriveVtxoKey(master, scope)
		if err != nil {
			return err
		}
		defer key.Key.Zero()
		if hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())) != d.CosignerPub {
			return fmt.Errorf("Light delegation scoped key mismatch")
		}
		// The SDK advertises the even lift of the x-only contract key. MuSig uses
		// compressed keys, so normalize the scalar as well as the public encoding.
		if key.PubKey().SerializeCompressed()[0] == 3 {
			key.Key.Negate()
		}
		return run(key)
	})
}
func validateDelegationCapability(d light.Descriptor, p lightDelegationPlan) (*vtxoPolicyTree, verifiedLightRenewalRegistration, error) {
	pins, err := deployment.IdentityFor(d.Network)
	if err != nil {
		return nil, verifiedLightRenewalRegistration{}, err
	}
	service := &Service{}
	service.Deployment.Network = d.Network
	tree, err := buildLightPolicyTree(d, mustDecodeRenewalHex(pins.OperatorSignerPubHex), service.vtxoAddrHRP())
	if err != nil {
		return nil, verifiedLightRenewalRegistration{}, err
	}
	script, err := delegationForfeitScript(d.Network)
	if err != nil {
		return nil, verifiedLightRenewalRegistration{}, err
	}
	expected, err := verifyLightDelegationRequest(p.Request, d, tree, script)
	if err != nil {
		return nil, verifiedLightRenewalRegistration{}, err
	}
	if !sameDelegationBytes(expected.Renewal, p.Renewal) || p.ValidAt != expected.ValidAt {
		return nil, verifiedLightRenewalRegistration{}, fmt.Errorf("Light delegation plan changed")
	}
	registration, err := verifyLightRegistration(p.Request.Intent.Proof, p.Request.Intent.Message, p.Renewal, d, tree, p.ValidAt, p.Request.ExpiresAt, append([]byte{2}, mustDecodeRenewalHex(d.CosignerPub)...))
	return tree, registration, err
}
func (k *fileBackedVaultKeys) authorizeLightDelegation(ctx context.Context, d light.Descriptor, p lightDelegationPlan, final *lightRenewalFinalEvidence) (string, error) {
	tree, registration, err := validateDelegationCapability(d, p)
	if err != nil {
		return "", err
	}
	raw := p.Request.Intent.Proof
	indexes := []int{0, 1}
	sighash := txscript.SigHashAll
	if final != nil {
		verified, err := verifyLightFinal(*final, p.Renewal, d, tree, registration, delegatedOwnerSighash)
		if err != nil {
			return "", err
		}
		packet, err := parsePSBT(verified.CanonicalForfeitPSBT)
		if err != nil {
			return "", err
		}
		packet.Inputs[0].SighashType = txscript.SigHashDefault
		raw, err = packet.B64Encode()
		if err != nil {
			return "", err
		}
		indexes = []int{0}
		sighash = txscript.SigHashDefault
	}
	var result string
	err = k.withDelegationKey(ctx, d, func(key *btcec.PrivateKey) error {
		var err error
		result, err = signExactVaultBoardStage(ctx, raw, key, mustDecodeRenewalHex(d.CosignerPub), tree.SpendLeaf, indexes, sighash)
		return err
	})
	return result, err
}
func verifyDelegationSigningTree(d light.Descriptor, p lightDelegationPlan, e lightDelegationTree) (*arktree.TxTree, *psbt.Packet, []byte, error) {
	tree, _, err := validateDelegationCapability(d, p)
	if err != nil {
		return nil, nil, nil, err
	}
	pins, err := deployment.IdentityFor(d.Network)
	if err != nil || e.BatchExpiry != pins.VtxoTreeExpirySeconds || len(e.BatchID) == 0 || len(e.BatchID) > 256 {
		return nil, nil, nil, fmt.Errorf("Light delegation batch binding")
	}
	commitment, err := parseCanonicalVaultBoardPSBT(e.CommitmentPSBT, maxVaultBoardProofBytes)
	if err != nil || commitment.UnsignedTx.Version != 2 || len(commitment.UnsignedTx.TxOut) < 2 {
		return nil, nil, nil, fmt.Errorf("Light delegation commitment")
	}
	_, graph, err := canonicalLightRenewalTree(e.VtxoTree)
	if err != nil {
		return nil, nil, nil, err
	}
	forfeit, err := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	if err != nil {
		return nil, nil, nil, err
	}
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: e.BatchExpiry}
	if err := arktree.ValidateVtxoTree(graph, commitment, forfeit, expiry); err != nil {
		return nil, nil, nil, err
	}
	if err := verifyVaultBoardBatchOutput(graph, commitment, forfeit, expiry); err != nil {
		return nil, nil, nil, err
	}
	receiver, _, err := findExactVaultBoardReceiver(graph, tree.PkScript, p.Renewal.ReceiverSats)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := graph.Find(receiver)
	if leaf == nil {
		return nil, nil, nil, fmt.Errorf("Light delegation receiver missing")
	}
	keys, err := txutils.ParseCosignerKeysFromArkPsbt(leaf.Root, 0)
	if err != nil || len(keys) != 2 {
		return nil, nil, nil, fmt.Errorf("Light delegation tree cosigners")
	}
	expected := "02" + d.CosignerPub
	owns := false
	for _, key := range keys {
		if hex.EncodeToString(key.SerializeCompressed()) == expected {
			owns = true
		}
	}
	if !owns || bytes.Equal(schnorr.SerializePubKey(keys[0]), schnorr.SerializePubKey(keys[1])) {
		return nil, nil, nil, fmt.Errorf("Light delegation tree identity")
	}
	sweep := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeit}}, Locktime: expiry}
	script, err := sweep.Script()
	if err != nil {
		return nil, nil, nil, err
	}
	root := txscript.NewBaseTapLeaf(script).TapHash()
	return graph, commitment, root[:], nil
}
func delegationTreeBinding(p lightDelegationPlan, e lightDelegationTree) (string, error) {
	raw, err := json.Marshal(struct {
		Plan lightDelegationPlan `json:"plan"`
		Tree lightDelegationTree `json:"tree"`
	}{p, e})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("vaulted-light/delegation-tree/v1:"), raw...))
	return hex.EncodeToString(sum[:]), nil
}
func delegationNonceAEAD(key *btcec.PrivateKey) (cipher.AEAD, error) {
	material := append([]byte("vaulted-light/delegation-nonce-key/v1:"), key.Serialize()...)
	sum := sha256.Sum256(material)
	zeroServiceBytes(material)
	defer zeroServiceBytes(sum[:])
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func delegationNodeNonces(key *btcec.PrivateKey, seed []byte, binding, txid string) (*musig2.Nonces, error) {
	reader := hkdf.New(sha256.New, seed, []byte(binding), []byte("vaulted-light/musig-nonce/v1:"+txid))
	return musig2.GenNonces(musig2.WithPublicKey(key.PubKey()), musig2.WithCustomRand(reader))
}
func delegationSigningNodes(graph *arktree.TxTree, key *btcec.PublicKey) (map[string]*psbt.Packet, error) {
	out := map[string]*psbt.Packet{}
	var walk func(*arktree.TxTree) error
	walk = func(node *arktree.TxTree) error {
		if node == nil {
			return nil
		}
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(node.Root, 0)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if bytes.Equal(k.SerializeCompressed(), key.SerializeCompressed()) {
				out[node.Root.UnsignedTx.TxID()] = node.Root
				break
			}
		}
		for _, child := range node.Children {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return out, walk(graph)
}
func (k *fileBackedVaultKeys) prepareLightDelegationTree(ctx context.Context, d light.Descriptor, p lightDelegationPlan, e lightDelegationTree) (lightDelegationNonceCapsule, error) {
	var result lightDelegationNonceCapsule
	graph, _, _, err := verifyDelegationSigningTree(d, p, e)
	if err != nil {
		return result, err
	}
	binding, err := delegationTreeBinding(p, e)
	if err != nil {
		return result, err
	}
	err = k.withDelegationKey(ctx, d, func(key *btcec.PrivateKey) error {
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
		if _, err := rand.Read(iv); err != nil {
			return err
		}
		nodes, err := delegationSigningNodes(graph, key.PubKey())
		if err != nil {
			return err
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
		result = lightDelegationNonceCapsule{binding, nonces, hex.EncodeToString(iv), hex.EncodeToString(aead.Seal(nil, iv, seed, []byte(binding)))}
		return nil
	})
	return result, err
}

// A fixed authenticated journal is bound by the composition root. The signer
// itself checks the persisted session and peer transcript before opening secrets;
// callers cannot reuse a capsule against a second MuSig challenge.
type lightDelegationJournal interface {
	ListLightDelegations(context.Context) ([]policy.LightDelegationSnapshot, error)
}

func (k *fileBackedVaultKeys) bindDelegationJournal(store lightDelegationJournal) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.delegationStore == nil {
		k.delegationStore = store
	}
}
func (k *fileBackedVaultKeys) verifyDelegationTranscript(ctx context.Context, d light.Descriptor, p lightDelegationPlan, prepared lightDelegationPreparedTree, all map[string]map[string]string) error {
	k.mu.RLock()
	store := k.delegationStore
	k.mu.RUnlock()
	if isNilInterface(store) {
		return fmt.Errorf("Light delegation signing journal unavailable")
	}
	snapshots, err := store.ListLightDelegations(ctx)
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		if snapshot.Operation.OperationID != p.Request.OperationID {
			continue
		}
		persisted, err := delegationStoredPlan(&snapshot, d)
		if err != nil || !sameDelegationBytes(persisted, p) {
			return fmt.Errorf("Light delegation signing plan not committed")
		}
		var tree lightDelegationPreparedTree
		var peers map[string]map[string]string
		if json.Unmarshal([]byte(snapshot.Events["tree_prepared"].Evidence), &tree) != nil || json.Unmarshal([]byte(snapshot.Events["nonces_committed"].Evidence), &peers) != nil || !sameDelegationBytes(tree, prepared) || !sameDelegationBytes(peers, all) {
			return fmt.Errorf("Light delegation signing transcript not committed")
		}
		switch snapshot.State() {
		case "nonces_committed", "tree_signed":
			return nil
		default:
			return fmt.Errorf("Light delegation signing session ended")
		}
	}
	return fmt.Errorf("Light delegation signing operation unavailable")
}
func (k *fileBackedVaultKeys) signLightDelegationTree(ctx context.Context, d light.Descriptor, p lightDelegationPlan, prepared lightDelegationPreparedTree, all map[string]map[string]string) (map[string]string, error) {
	if err := k.verifyDelegationTranscript(ctx, d, p, prepared, all); err != nil {
		return nil, err
	}
	graph, commitment, root, err := verifyDelegationSigningTree(d, p, prepared.Tree)
	if err != nil {
		return nil, err
	}
	binding, err := delegationTreeBinding(p, prepared.Tree)
	if err != nil || binding != prepared.Capsule.Binding {
		return nil, fmt.Errorf("Light delegation nonce binding")
	}
	result := map[string]string{}
	err = k.withDelegationKey(ctx, d, func(key *btcec.PrivateKey) error {
		aead, err := delegationNonceAEAD(key)
		if err != nil {
			return err
		}
		iv, err := hex.DecodeString(prepared.Capsule.IV)
		if err != nil || len(iv) != aead.NonceSize() {
			return fmt.Errorf("Light delegation nonce IV")
		}
		encrypted, err := hex.DecodeString(prepared.Capsule.Ciphertext)
		if err != nil {
			return err
		}
		seed, err := aead.Open(nil, iv, encrypted, []byte(binding))
		if err != nil {
			return err
		}
		defer zeroServiceBytes(seed)
		nodes, err := delegationSigningNodes(graph, key.PubKey())
		if err != nil || len(nodes) != len(all) || len(nodes) != len(prepared.Capsule.Nonces) {
			return fmt.Errorf("Light delegation nonce coverage")
		}
		for txid, packet := range nodes {
			nonces := all[txid]
			keys, err := txutils.ParseCosignerKeysFromArkPsbt(packet, 0)
			if err != nil || len(keys) != len(nonces) {
				return fmt.Errorf("Light delegation nonce participants")
			}
			nonce, err := delegationNodeNonces(key, seed, binding, txid)
			if err != nil {
				return err
			}
			defer zeroServiceBytes(nonce.SecNonce[:])
			own := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
			if hex.EncodeToString(nonce.PubNonce[:]) != prepared.Capsule.Nonces[txid] || nonces[own] != prepared.Capsule.Nonces[txid] {
				return fmt.Errorf("Light delegation own nonce changed")
			}
			public := make([][66]byte, 0, len(keys))
			for _, pub := range keys {
				raw, err := hex.DecodeString(nonces[hex.EncodeToString(schnorr.SerializePubKey(pub))])
				if err != nil || len(raw) != 66 {
					return fmt.Errorf("Light delegation peer nonce")
				}
				public = append(public, [66]byte(raw))
			}
			aggregate, err := musig2.AggregateNonces(public)
			if err != nil {
				return err
			}
			previous := packet.UnsignedTx.TxIn[0].PreviousOutPoint
			prevout := commitment.UnsignedTx.TxOut[0]
			if previous.Hash != commitment.UnsignedTx.TxHash() {
				parent := graph.Find(previous.Hash.String())
				if parent == nil || int(previous.Index) >= len(parent.Root.UnsignedTx.TxOut) {
					return fmt.Errorf("Light delegation signing parent")
				}
				prevout = parent.Root.UnsignedTx.TxOut[previous.Index]
			}
			fetcher := txscript.NewCannedPrevOutputFetcher(prevout.PkScript, prevout.Value)
			digest, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(packet.UnsignedTx, fetcher), txscript.SigHashDefault, packet.UnsignedTx, 0, fetcher)
			if err != nil {
				return err
			}
			sig, err := musig2.Sign(nonce.SecNonce, key, aggregate, keys, [32]byte(digest), musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(root))
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err := sig.Encode(&buf); err != nil {
				return err
			}
			result[txid] = hex.EncodeToString(buf.Bytes())
		}
		return nil
	})
	return result, err
}

func (k *fileBackedVaultKeys) authorizeLightDelegationDelete(ctx context.Context, d light.Descriptor, p lightDelegationPlan) (string, error) {
	tree, _, err := validateDelegationCapability(d, p)
	if err != nil {
		return "", err
	}
	k.mu.RLock()
	store := k.delegationStore
	k.mu.RUnlock()
	if isNilInterface(store) {
		return "", fmt.Errorf("Light delegation signing journal unavailable")
	}
	all, err := store.ListLightDelegations(ctx)
	if err != nil {
		return "", err
	}
	matched := false
	for _, snapshot := range all {
		if snapshot.Operation.OperationID != p.Request.OperationID {
			continue
		}
		saved, err := delegationStoredPlan(&snapshot, d)
		if err != nil || !sameDelegationBytes(saved, p) || snapshot.State() != "cleanup_pending" {
			return "", fmt.Errorf("Light delegation abandonment not committed")
		}
		matched = true
	}
	if !matched {
		return "", fmt.Errorf("Light delegation cleanup unavailable")
	}
	var result string
	err = k.withDelegationKey(ctx, d, func(key *btcec.PrivateKey) error {
		var err error
		result, err = signExactVaultBoardStage(ctx, p.Request.DeleteIntent.Proof, key, mustDecodeRenewalHex(d.CosignerPub), tree.SpendLeaf, []int{0, 1}, txscript.SigHashAll)
		return err
	})
	return result, err
}
