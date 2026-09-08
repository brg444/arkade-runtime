package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func rollingFinalFixture(t *testing.T) (*env, *RollingOperations, *fileBackedVaultKeys, string, rollingRenewalFinalEvidence) {
	t.Helper()
	return rollingFinalFixtureWithHeaders(t, nil)
}

type rollingFinalClockCrossing struct {
	rollingOperationAuthorizer
	before func()
}

func (k rollingFinalClockCrossing) authorizeRollingFinal(ctx context.Context, vault, id string) (rollingFinalAuthorization, error) {
	k.before()
	return k.rollingOperationAuthorizer.authorizeRollingFinal(ctx, vault, id)
}

func TestRollingFinalClockCrossingRetainsFenceWithoutNewSignature(t *testing.T) {
	e, manager, keys, id, evidence := rollingFinalFixture(t)
	_, resolver, err := keys.rollingDependencies()
	if err != nil {
		t.Fatal(err)
	}
	e.svc.keys.rollingOperation = rollingFinalClockCrossing{rollingOperationAuthorizer: keys, before: func() {
		keys.bindRollingJournal(rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(24 * time.Hour)}, resolver)
	}}
	if _, err = e.svc.prepareRollingFinal(t.Context(), manager, id, evidence); err == nil {
		t.Fatal("expired final capability signed")
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["final_authorized"].Evidence == "" || record.Events["final_signed"].Evidence != "" {
		t.Fatal("clock crossing lost authority fence or retained signatures", err)
	}
	if _, err = e.svc.prepareRollingCleanup(t.Context(), manager, id); err == nil {
		t.Fatal("clock crossing reopened cleanup")
	}
}

func TestRollingFinalExpiredReplayDoesNotUseMasterKey(t *testing.T) {
	e, manager, keys, id, evidence := rollingFinalFixture(t)
	auth, err := e.svc.prepareRollingFinal(t.Context(), manager, id, evidence)
	if err != nil {
		t.Fatal(err)
	}
	_, resolver, err := keys.rollingDependencies()
	if err != nil {
		t.Fatal(err)
	}
	keys.bindRollingJournal(rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(48 * time.Hour)}, resolver)
	keys.wipe()
	replayed, err := e.svc.prepareRollingFinal(t.Context(), manager, id, evidence)
	if err != nil || !reflect.DeepEqual(auth, replayed) {
		t.Fatal("expired retained response required signing or changed", err)
	}
	if _, err = e.svc.prepareRollingCleanup(t.Context(), manager, id); err == nil {
		t.Fatal("expired retained signatures reopened cleanup")
	}
}

func rollingFinalFixtureWithHeaders(t *testing.T, mutate func(*arktree.TxTree)) (*env, *RollingOperations, *fileBackedVaultKeys, string, rollingRenewalFinalEvidence) {
	return rollingFinalFixtureBuild(t, mutate, true)
}

func rollingFinalFixtureBuild(t *testing.T, mutate func(*arktree.TxTree), stages bool, capture ...func(*btcec.PrivateKey)) (*env, *RollingOperations, *fileBackedVaultKeys, string, rollingRenewalFinalEvidence) {
	t.Helper()
	e, manager, keys, _, id := rollingRenewalApplicationFixture(t)
	authorizeRollingFixture(t, e, manager, id)
	record, err := manager.operation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	p := record.Operation.Proposal
	pins, err := deployment.IdentityFor(record.Enrollment.Network)
	if err != nil {
		t.Fatal(err)
	}
	forfeitPub, err := btcec.ParsePubKey(mustDecodeRenewalHex(pins.CheckpointForfeitPubHex))
	if err != nil {
		t.Fatal(err)
	}
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: pins.VtxoTreeExpirySeconds}
	sweep := &arkscript.CSVMultisigClosure{MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPub}}, Locktime: expiry}
	sweepScript, err := sweep.Script()
	if err != nil {
		t.Fatal(err)
	}
	root := txscript.NewBaseTapLeaf(sweepScript).TapHash()
	delegate, err := deriveRollingDelegateKey(e.master, rollingKeyContext{vault: fixture.VaultID, network: record.Enrollment.Network, operator: manager.contract.Keys.Operator.SerializeCompressed()})
	if err != nil {
		t.Fatal(err)
	}
	defer delegate.Key.Zero()
	operatorSession, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, save := range capture {
		save(operatorSession)
	}
	ext, err := extension.NewExtensionFromTx(p.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	mapped := extension.Extension{}
	for _, packet := range ext {
		if assets, ok := packet.(asset.Packet); ok {
			mapped = append(mapped, assets.LeafTxPacket(p.Transaction.TxHash()))
		} else {
			mapped = append(mapped, packet)
		}
	}
	marker, err := mapped.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	outputs := []arktree.LeafOutput{}
	for i, out := range p.Transaction.TxOut {
		script := out.PkScript
		if i == len(p.Transaction.TxOut)-1 {
			script = marker
		}
		outputs = append(outputs, arktree.LeafOutput{Amount: uint64(out.Value), Script: hex.EncodeToString(script)})
	}
	leaves := []arktree.Leaf{{Outputs: outputs, CosignersPublicKeys: []string{hex.EncodeToString(delegate.PubKey().SerializeCompressed()), hex.EncodeToString(operatorSession.PubKey().SerializeCompressed())}}}
	// Include another participant's output so the owned recovery path has
	// both an ancestor and a leaf. The fixture keys sign the whole graph.
	leaves = append(leaves, arktree.Leaf{Outputs: []arktree.LeafOutput{{Amount: 1111, Script: hex.EncodeToString(manager.contract.PkScript)}}, CosignersPublicKeys: leaves[0].CosignersPublicKeys})
	batchScript, batchValue, err := arktree.BuildBatchOutput(leaves, root[:])
	if err != nil {
		t.Fatal(err)
	}
	connectorScript, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(operatorSession.PubKey()))
	if err != nil {
		t.Fatal(err)
	}
	connectorLeaves := []arktree.Leaf{}
	for range p.Sources {
		connectorLeaves = append(connectorLeaves, arktree.Leaf{Outputs: []arktree.LeafOutput{{Amount: 330, Script: hex.EncodeToString(connectorScript)}}, CosignersPublicKeys: []string{hex.EncodeToString(operatorSession.PubKey().SerializeCompressed())}})
	}
	connectorRoot, connectorValue, err := arktree.BuildConnectorOutput(connectorLeaves)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := psbt.New([]*wire.OutPoint{{Hash: chainhash.Hash{7}}}, []*wire.TxOut{{Value: batchValue, PkScript: batchScript}, {Value: connectorValue, PkScript: connectorRoot}}, 2, 0, []uint32{wire.MaxTxInSequenceNum})
	if err != nil {
		t.Fatal(err)
	}
	vtxos, err := arktree.BuildVtxoTree(&wire.OutPoint{Hash: commitment.UnsignedTx.TxHash()}, leaves, root[:], expiry)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(vtxos)
		var rebind func(*arktree.TxTree)
		rebind = func(node *arktree.TxTree) {
			for index, child := range node.Children {
				child.Root.UnsignedTx.TxIn[0].PreviousOutPoint = wire.OutPoint{Hash: node.Root.UnsignedTx.TxHash(), Index: index}
				rebind(child)
			}
		}
		rebind(vtxos)
	}
	coordinator, err := arktree.NewTreeCoordinatorSession(root[:], batchValue, vtxos)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[*btcec.PrivateKey]arktree.SignerSession{}
	for _, key := range []*btcec.PrivateKey{delegate, operatorSession} {
		session := arktree.NewTreeSignerSession(key)
		if err = session.Init(root[:], batchValue, vtxos); err != nil {
			t.Fatal(err)
		}
		nonces, err := session.GetNonces()
		if err != nil {
			t.Fatal(err)
		}
		coordinator.AddNonce(key.PubKey(), nonces)
		sessions[key] = session
	}
	aggregate, err := coordinator.AggregateNonces()
	if err != nil {
		t.Fatal(err)
	}
	for key, session := range sessions {
		session.SetAggregatedNonces(aggregate)
		sigs, err := session.Sign()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = coordinator.AddSignatures(key.PubKey(), sigs); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := coordinator.SignTree()
	if err != nil {
		t.Fatal(err)
	}
	flat, err := signed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	connectors, err := arktree.BuildConnectorTree(&wire.OutPoint{Hash: commitment.UnsignedTx.TxHash(), Index: 1}, connectorLeaves)
	if err != nil {
		t.Fatal(err)
	}
	connectorFlat, err := connectors.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	emu, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	tweaked := arkade.ComputeArkadeScriptPrivateKey(emu, arkade.ArkadeScriptHash(manager.contract.Programs.Renew))
	destination := append([]byte{txscript.OP_0, 0x14}, btcutil.Hash160(forfeitPub.SerializeCompressed())...)
	forfeits := []string{}
	connectorPackets := connectors.Leaves()
	for i, source := range p.Sources {
		connector := connectorPackets[i]
		forfeit, err := arktree.BuildForfeitTx([]*wire.OutPoint{{Hash: source.Previous.TxHash(), Index: source.Index}, {Hash: connector.UnsignedTx.TxHash()}}, []uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum}, []*wire.TxOut{source.Previous.TxOut[source.Index], connector.UnsignedTx.TxOut[0]}, destination, 0)
		if err != nil {
			t.Fatal(err)
		}
		forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{manager.contract.Renew}
		sig, err := signTapLeafAt(forfeit, 0, tweaked, manager.contract.Renew.Script)
		if err != nil {
			t.Fatal(err)
		}
		forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
		raw, err := forfeit.B64Encode()
		if err != nil {
			t.Fatal(err)
		}
		forfeits = append(forfeits, raw)
	}
	commitmentRaw, err := commitment.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	evidence := rollingRenewalFinalEvidence{BatchID: "rolling-batch", BatchExpiry: pins.VtxoTreeExpirySeconds, CommitmentPSBT: commitmentRaw, VtxoTree: flat, Connectors: connectorFlat, ForfeitPSBTs: forfeits}
	for _, phase := range []string{"emulator_authorized", "register_dispatched", "registered"} {
		if _, err = e.ledger.AppendRollingEvent(t.Context(), policy.RollingEvent{OperationID: id, Phase: phase, Evidence: `{}`}); err != nil {
			t.Fatal(err)
		}
	}
	if stages && mutate == nil {
		prepared, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, rollingUnsignedTreeFixture(t, evidence))
		if err != nil {
			t.Fatal(err)
		}
		peers := rollingPeerNoncesFixture(t, manager.contract, prepared)
		if _, err = e.svc.signRollingRenewalTree(t.Context(), manager, id, peers); err != nil {
			t.Fatal(err)
		}
	}
	return e, manager, keys, id, evidence
}

func TestRollingFinalRejectsCorrectlySignedDelayedRecovery(t *testing.T) {
	for _, location := range []string{"ancestor", "leaf"} {
		for _, delay := range []string{"absolute", "relative"} {
			t.Run(location+"/"+delay, func(t *testing.T) {
				_, manager, _, id, evidence := rollingFinalFixtureWithHeaders(t, func(graph *arktree.TxTree) {
					target := graph.Root.UnsignedTx
					if location == "leaf" {
						for _, leaf := range graph.Leaves() {
							if len(leaf.UnsignedTx.TxOut) > 2 {
								target = leaf.UnsignedTx
								break
							}
						}
					}
					if delay == "absolute" {
						target.LockTime = 2_000_000_000
						target.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1
					} else {
						target.TxIn[0].Sequence = 0x0040ffff
					}
				})
				record, err := manager.operation(t.Context(), id)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = verifyRollingRenewalFinal(manager.contract, record, evidence); err == nil {
					t.Fatal("valid signatures concealed delayed recovery")
				}
			})
		}
	}
}

func TestRollingFinalRequiresDurableCompleteRecoveryBeforeGuardian(t *testing.T) {
	e, manager, keys, id, evidence := rollingFinalFixture(t)
	if _, err := keys.authorizeRollingFinal(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("forfeits signed without retained recovery")
	}
	auth, err := e.svc.prepareRollingFinal(t.Context(), manager, id, evidence)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := e.svc.prepareRollingFinal(t.Context(), manager, id, evidence)
	if err != nil || !reflect.DeepEqual(auth, retry) {
		t.Fatal("final retry changed authority", err)
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["final_signed"].Evidence == "" || record.Events["final_authorized"].Evidence == "" {
		t.Fatal("final authority or signatures not retained", err)
	}
	if _, err = e.svc.prepareRollingCleanup(t.Context(), manager, id); err == nil {
		t.Fatal("final authority allowed conflicting cleanup")
	}
	if _, err = e.ledger.AppendRollingEvent(t.Context(), policy.RollingEvent{OperationID: id, Phase: "submitted"}); err != nil {
		t.Fatal(err)
	}
	verified, err := verifyRollingRenewalFinal(manager.contract, record, evidence)
	if err != nil {
		t.Fatal(err)
	}
	bad := verified.Batch
	bad.CommitmentTxid = id
	if err = verifyRollingRetainedBatch(manager.contract, record, bad); err == nil {
		t.Fatal("finalization substituted retained commitment")
	}
	if err = verifyRollingRetainedBatch(manager.contract, record, verified.Batch); err != nil {
		t.Fatal(err)
	}
}

func TestRollingCleanupPreventsFinalGuardianSignature(t *testing.T) {
	e, manager, keys, id, evidence := rollingFinalFixture(t)
	if _, err := e.svc.prepareRollingCleanup(t.Context(), manager, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.prepareRollingFinal(t.Context(), manager, id, evidence); err == nil {
		t.Fatal("cleanup permitted final authority")
	}
	if _, err := keys.authorizeRollingFinal(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("cleanup permitted final signature")
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["final_authorized"].Evidence != "" || record.Events["final_signed"].Evidence != "" {
		t.Fatal("cleanup persisted conflicting authority", err)
	}
}

func TestRollingFinalRejectsIncompleteOrAlteredRecovery(t *testing.T) {
	_, manager, _, id, original := rollingFinalFixture(t)
	record, err := manager.operation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*rollingRenewalFinalEvidence){
		"different batch session":   func(e *rollingRenewalFinalEvidence) { e.BatchID = "another-batch" },
		"missing graph":             func(e *rollingRenewalFinalEvidence) { e.VtxoTree = nil },
		"wrong expiry":              func(e *rollingRenewalFinalEvidence) { e.BatchExpiry++ },
		"missing connectors":        func(e *rollingRenewalFinalEvidence) { e.Connectors = nil },
		"missing principal forfeit": func(e *rollingRenewalFinalEvidence) { e.ForfeitPSBTs = e.ForfeitPSBTs[:1] },
		"duplicate source":          func(e *rollingRenewalFinalEvidence) { e.ForfeitPSBTs[1] = e.ForfeitPSBTs[0] },
		"unsigned recovery": func(e *rollingRenewalFinalEvidence) {
			p, _ := parsePSBT(e.VtxoTree[0].Tx)
			p.Inputs[0].TaprootKeySpendSig = nil
			e.VtxoTree[0].Tx, _ = p.B64Encode()
		},
		"invalid emulator signature": func(e *rollingRenewalFinalEvidence) {
			p, _ := parsePSBT(e.ForfeitPSBTs[0])
			p.Inputs[0].TaprootScriptSpendSig[0].Signature[0] ^= 1
			e.ForfeitPSBTs[0], _ = p.B64Encode()
		},
		"cleanup leaf": func(e *rollingRenewalFinalEvidence) {
			p, _ := parsePSBT(e.ForfeitPSBTs[0])
			p.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{manager.contract.Cleanup}
			e.ForfeitPSBTs[0], _ = p.B64Encode()
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var bad rollingRenewalFinalEvidence
			if err = json.Unmarshal(raw, &bad); err != nil {
				t.Fatal(err)
			}
			mutate(&bad)
			if _, err = verifyRollingRenewalFinal(manager.contract, record, bad); err == nil {
				t.Fatal("unsafe recovery authorized")
			}
		})
	}
}
