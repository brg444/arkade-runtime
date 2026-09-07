package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// The stock Operator sends the shared parent, with all child references, but
// only the descendant transactions belonging to the subscribed participant.
func TestRenewalCapturedStockParticipantPaths(t *testing.T) {
	raw, err := os.ReadFile("testdata/renewal-stock-pruned-trees.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]lightDelegationTree
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	pins, _ := deployment.IdentityFor("mutinynet")
	forfeit, _ := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	for tier, fixture := range fixtures {
		t.Run(tier, func(t *testing.T) {
			flat, graph, err := canonicalLightRenewalTree(fixture.VtxoTree)
			if err != nil {
				t.Fatal(err)
			}
			if len(flat) != 2 || len(graph.Children) != 1 {
				t.Fatal("expected shared root and one owned leaf")
			}
			for _, node := range flat {
				if node.Txid == graph.Root.UnsignedTx.TxID() && len(node.Children) != 2 {
					t.Fatal("pruning changed signed transcript metadata")
				}
			}
			commitment, err := parsePSBT(fixture.CommitmentPSBT)
			if err != nil {
				t.Fatal(err)
			}
			expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: fixture.BatchExpiry}
			if err := arktree.ValidateVtxoTree(graph, commitment, forfeit, expiry); err != nil {
				t.Fatal(err)
			}
			if err := verifyVaultBoardBatchOutput(graph, commitment, forfeit, expiry); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func participantPath(t *testing.T, full arktree.FlatTxTree, script []byte) arktree.FlatTxTree {
	t.Helper()
	var leafID string
	for _, node := range full {
		if len(node.Children) == 0 {
			p, _ := parsePSBT(node.Tx)
			for _, out := range p.UnsignedTx.TxOut {
				if bytes.Equal(out.PkScript, script) {
					leafID = node.Txid
				}
			}
		}
	}
	if leafID == "" {
		t.Fatal("fixture receiver not found")
	}
	keep := map[string]bool{leafID: true}
	for changed := true; changed; {
		changed = false
		for _, node := range full {
			for _, child := range node.Children {
				if keep[child] && !keep[node.Txid] {
					keep[node.Txid] = true
					changed = true
				}
			}
		}
	}
	var path arktree.FlatTxTree
	for _, node := range full {
		if keep[node.Txid] {
			path = append(path, node)
		}
	}
	return path
}

func TestRenewalPrunedPathRequiresCompleteSignedRecovery(t *testing.T) {
	f := newLightRenewalProofFixture(t)
	owner, _ := btcec.NewPrivateKey()
	operator, _ := btcec.NewPrivateKey()
	other, _ := btcec.NewPrivateKey()
	f, registered, full := buildLightRenewalFinalFixture(t, f, owner, operator, other)
	e := full
	e.VtxoTree = participantPath(t, full.VtxoTree, f.tree.PkScript)
	if len(e.VtxoTree) != 2 || len(full.VtxoTree) != 3 {
		t.Fatal("expected two-participant fixture")
	}
	if _, err := verifyLightRenewalFinal(e, f.plan, f.descriptor, f.tree, registered); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*lightRenewalFinalEvidence){
		"missing owned leaf": func(e *lightRenewalFinalEvidence) {
			for i, n := range e.VtxoTree {
				if len(n.Children) == 0 {
					e.VtxoTree = append(e.VtxoTree[:i], e.VtxoTree[i+1:]...)
					return
				}
			}
		},
		"missing shared root": func(e *lightRenewalFinalEvidence) {
			for i, n := range e.VtxoTree {
				if len(n.Children) > 0 {
					e.VtxoTree = append(e.VtxoTree[:i], e.VtxoTree[i+1:]...)
					return
				}
			}
		},
		"missing root signature": func(e *lightRenewalFinalEvidence) {
			for i, n := range e.VtxoTree {
				if len(n.Children) > 0 {
					p, _ := parsePSBT(n.Tx)
					p.Inputs[0].TaprootKeySpendSig = nil
					e.VtxoTree[i].Tx, _ = p.B64Encode()
				}
			}
		},
		"invalid leaf signature": func(e *lightRenewalFinalEvidence) {
			for i, n := range e.VtxoTree {
				if len(n.Children) == 0 {
					p, _ := parsePSBT(n.Tx)
					p.Inputs[0].TaprootKeySpendSig = bytes.Repeat([]byte{7}, 64)
					e.VtxoTree[i].Tx, _ = p.B64Encode()
				}
			}
		},
		"wrong recipient": func(e *lightRenewalFinalEvidence) {
			e.VtxoTree = nil
			for _, n := range full.VtxoTree {
				keep := len(n.Children) > 0
				if !keep {
					p, _ := parsePSBT(n.Tx)
					keep = !bytes.Equal(p.UnsignedTx.TxOut[0].PkScript, f.tree.PkScript)
				}
				if keep {
					e.VtxoTree = append(e.VtxoTree, n)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := e
			changed.VtxoTree = append(arktree.FlatTxTree(nil), e.VtxoTree...)
			mutate(&changed)
			if _, err := verifyLightRenewalFinal(changed, f.plan, f.descriptor, f.tree, registered); err == nil {
				t.Fatal("invalid recovery path accepted")
			}
		})
	}
}

func TestRenewalDelegationSignsOnlyProvidedOwnedPath(t *testing.T) {
	other, _ := btcec.NewPrivateKey()
	f := newDelegatedFixture(t, other)
	f.tree.VtxoTree = participantPath(t, f.tree.VtxoTree, f.f.tree.PkScript)
	capsule, err := f.f.env.svc.keys.lightDelegation.prepareLightDelegationTree(t.Context(), f.f.descriptor, f.p, f.tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(capsule.Nonces) != 2 {
		t.Fatalf("nonces for %d nodes, want shared root and owned leaf", len(capsule.Nonces))
	}
}

func TestRenewalPrunedGraphBounds(t *testing.T) {
	raw, err := os.ReadFile("testdata/renewal-stock-pruned-trees.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]lightDelegationTree
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	original := fixtures["standard"].VtxoTree
	rootID := original.RootTxid()
	for name, mutate := range map[string]func(arktree.FlatTxTree) arktree.FlatTxTree{
		"duplicate node": func(f arktree.FlatTxTree) arktree.FlatTxTree { return append(f, f[0]) },
		"self reference": func(f arktree.FlatTxTree) arktree.FlatTxTree {
			for i, n := range f {
				if n.Txid == rootID {
					f[i].Children[0] = n.Txid
				}
			}
			return f
		},
		"repeated child": func(f arktree.FlatTxTree) arktree.FlatTxTree {
			for i, n := range f {
				if n.Txid == rootID {
					f[i].Children[1] = n.Children[0]
				}
			}
			return f
		},
		"out of bounds missing sibling": func(f arktree.FlatTxTree) arktree.FlatTxTree {
			for i, n := range f {
				if n.Txid == rootID {
					f[i].Children[999] = n.Children[1]
					delete(f[i].Children, 1)
				}
			}
			return f
		},
		"anchor child": func(f arktree.FlatTxTree) arktree.FlatTxTree {
			for i, n := range f {
				if n.Txid == rootID {
					f[i].Children[2] = n.Children[1]
					delete(f[i].Children, 1)
				}
			}
			return f
		},
		"disconnected owned leaf": func(f arktree.FlatTxTree) arktree.FlatTxTree {
			for i, n := range f {
				if n.Txid == rootID {
					delete(f[i].Children, 0)
				}
			}
			return f
		},
		"no descendant": func(f arktree.FlatTxTree) arktree.FlatTxTree {
			for _, n := range f {
				if n.Txid == rootID {
					return arktree.FlatTxTree{n}
				}
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var f arktree.FlatTxTree
			_ = json.Unmarshal(raw, &f)
			if _, _, err := canonicalLightRenewalTree(mutate(f)); err == nil {
				t.Fatal("malformed graph accepted")
			}
		})
	}
	if _, err := canonicalVaultBoardTree(original); err == nil {
		t.Fatal("boarding must still reject dangling children")
	}
}

func TestRenewalPrunedConnectorPath(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	var leaves []arktree.Leaf
	var owned []byte
	for i := 0; i < 5; i++ {
		receiver, _ := btcec.NewPrivateKey()
		script, _ := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(receiver.PubKey()))
		if i == 0 {
			owned = script
		}
		leaves = append(leaves, arktree.Leaf{Outputs: []arktree.LeafOutput{{Amount: 330, Script: hex.EncodeToString(script)}}, CosignersPublicKeys: []string{hex.EncodeToString(key.PubKey().SerializeCompressed())}})
	}
	full, err := arktree.BuildConnectorTree(&wire.OutPoint{Hash: chainhash.Hash{1}, Index: 1}, leaves)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := full.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	path := participantPath(t, serialized, owned)
	flat, graph, err := canonicalLightRenewalTree(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flat) >= len(serialized) {
		t.Fatal("connector fixture was not pruned")
	}
	if err := graph.Validate(); err != nil {
		t.Fatal(err)
	}
	leaf := graph.Leaves()[0]
	if !bytes.Equal(leaf.UnsignedTx.TxOut[0].PkScript, owned) {
		t.Fatal("wrong connector path")
	}
	for i, n := range flat {
		if n.Txid == leaf.UnsignedTx.TxID() {
			flat = append(flat[:i], flat[i+1:]...)
			break
		}
	}
	if _, _, err := canonicalLightRenewalTree(flat); err == nil {
		t.Fatal("missing connector descendant accepted")
	}
}

func TestRenewalPrunedRecoveryRejectsMissingIntermediateAncestor(t *testing.T) {
	f := newLightRenewalProofFixture(t)
	owner, _ := btcec.NewPrivateKey()
	operator, _ := btcec.NewPrivateKey()
	var others []*btcec.PrivateKey
	for i := 0; i < 4; i++ {
		key, _ := btcec.NewPrivateKey()
		others = append(others, key)
	}
	f, registered, e := buildLightRenewalFinalFixture(t, f, owner, operator, others...)
	e.VtxoTree = participantPath(t, e.VtxoTree, f.tree.PkScript)
	if len(e.VtxoTree) < 3 {
		t.Fatal("fixture must have an intermediate ancestor")
	}
	if _, err := verifyLightRenewalFinal(e, f.plan, f.descriptor, f.tree, registered); err != nil {
		t.Fatal(err)
	}
	rootID := e.VtxoTree.RootTxid()
	for i, n := range e.VtxoTree {
		if len(n.Children) > 0 && n.Txid != rootID {
			e.VtxoTree = append(e.VtxoTree[:i], e.VtxoTree[i+1:]...)
			break
		}
	}
	if _, err := verifyLightRenewalFinal(e, f.plan, f.descriptor, f.tree, registered); err == nil {
		t.Fatal("missing recovery ancestor accepted")
	}
}
