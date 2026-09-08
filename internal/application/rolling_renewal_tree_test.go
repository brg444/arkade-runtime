package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

func rollingUnsignedTreeFixture(t *testing.T, e rollingRenewalFinalEvidence) rollingRenewalTree {
	t.Helper()
	flat, _, err := canonicalLightRenewalTree(e.VtxoTree)
	if err != nil {
		t.Fatal(err)
	}
	for i := range flat {
		p, err := parsePSBT(flat[i].Tx)
		if err != nil {
			t.Fatal(err)
		}
		p.Inputs[0].TaprootKeySpendSig = nil
		flat[i].Tx, err = p.B64Encode()
		if err != nil {
			t.Fatal(err)
		}
	}
	return rollingRenewalTree{BatchID: e.BatchID, BatchExpiry: e.BatchExpiry, CommitmentPSBT: e.CommitmentPSBT, VtxoTree: flat}
}

func rollingPeerNoncesFixture(t *testing.T, c *rolling.Contract, prepared rollingPreparedTree) map[string]map[string]string {
	t.Helper()
	_, graph, err := canonicalLightRenewalTree(prepared.Tree.VtxoTree)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := btcec.ParsePubKey(c.Parameters.DelegatePubkey)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := delegationSigningNodes(graph, pub)
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]map[string]string{}
	for txid, p := range nodes {
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(p, 0)
		if err != nil {
			t.Fatal(err)
		}
		all[txid] = map[string]string{}
		for _, key := range keys {
			name := hex.EncodeToString(schnorr.SerializePubKey(key))
			if name == hex.EncodeToString(schnorr.SerializePubKey(pub)) {
				all[txid][name] = prepared.Capsule.Nonces[txid]
				continue
			}
			nonce, err := musig2.GenNonces(musig2.WithPublicKey(key))
			if err != nil {
				t.Fatal(err)
			}
			all[txid][name] = hex.EncodeToString(nonce.PubNonce[:])
			zeroServiceBytes(nonce.SecNonce[:])
		}
	}
	return all
}

func TestRollingTreeRetainsNonceTranscriptAndReplaysWithoutMaster(t *testing.T) {
	e, manager, keys, id, evidence := rollingFinalFixtureBuild(t, nil, false)
	if _, err := keys.prepareRollingTree(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("key accepted unretained tree")
	}
	if _, err := keys.signRollingTree(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("key signed without retained nonces")
	}
	tree := rollingUnsignedTreeFixture(t, evidence)
	prepared, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, tree)
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["tree_prepared"].Evidence == "" || record.Events["tree_requested"].Evidence == "" {
		t.Fatal("public nonces escaped retention", err)
	}
	retry, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, tree)
	if err != nil || !reflect.DeepEqual(prepared, retry) {
		t.Fatal("nonce seed regenerated", err)
	}
	other := tree
	other.BatchID = "another-session"
	if _, err = e.svc.prepareRollingRenewalTree(t.Context(), manager, id, other); err == nil {
		t.Fatal("session replacement accepted")
	}
	peers := rollingPeerNoncesFixture(t, manager.contract, prepared)
	signed, err := e.svc.signRollingRenewalTree(t.Context(), manager, id, peers)
	if err != nil {
		t.Fatal(err)
	}
	record, err = manager.operation(t.Context(), id)
	if err != nil || record.Events["tree_signed"].Evidence == "" || record.Events["nonces_committed"].Evidence == "" {
		t.Fatal("partials escaped retention", err)
	}
	_, resolver, err := keys.rollingDependencies()
	if err != nil {
		t.Fatal(err)
	}
	keys.bindRollingJournal(rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(24 * time.Hour)}, resolver)
	keys.wipe()
	replayed, err := e.svc.signRollingRenewalTree(t.Context(), manager, id, peers)
	if err != nil || !reflect.DeepEqual(signed, replayed) {
		t.Fatal("retained partials were regenerated", err)
	}
	changed := rollingPeerNoncesFixture(t, manager.contract, prepared)
	if _, err = e.svc.signRollingRenewalTree(t.Context(), manager, id, changed); err == nil {
		t.Fatal("nonce reused against changed peers")
	}
}

func TestRollingTreeRefusesIncompleteNoncesBeforeJournalCommit(t *testing.T) {
	e, manager, _, id, evidence := rollingFinalFixtureBuild(t, nil, false)
	prepared, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, rollingUnsignedTreeFixture(t, evidence))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"node", "participant", "own", "extra node", "extra participant", "invalid point"} {
		t.Run(mutation, func(t *testing.T) {
			peers := rollingPeerNoncesFixture(t, manager.contract, prepared)
			for txid, nonces := range peers {
				switch mutation {
				case "node":
					delete(peers, txid)
				case "participant":
					for key := range nonces {
						delete(nonces, key)
						break
					}
				case "own":
					nonces[hex.EncodeToString(manager.contract.Parameters.DelegatePubkey[1:])] = "00"
				case "extra node":
					peers["unknown"] = nonces
				case "extra participant":
					nonces["unknown"] = "00"
				case "invalid point":
					for key := range nonces {
						if key != hex.EncodeToString(manager.contract.Parameters.DelegatePubkey[1:]) {
							nonces[key] = hex.EncodeToString(make([]byte, 66))
							break
						}
					}
				}
				break
			}
			if _, err := e.svc.signRollingRenewalTree(t.Context(), manager, id, peers); err == nil {
				t.Fatal("invalid peer transcript accepted")
			}
			record, err := manager.operation(t.Context(), id)
			if err != nil || record.Events["nonces_committed"].Evidence != "" {
				t.Fatal("invalid peers consumed session", err)
			}
		})
	}
}

func TestRollingTreeCleanupAndExpiryPreventFreshPartials(t *testing.T) {
	for _, stop := range []string{"cleanup", "expiry"} {
		t.Run(stop, func(t *testing.T) {
			e, manager, keys, id, evidence := rollingFinalFixtureBuild(t, nil, false)
			prepared, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, rollingUnsignedTreeFixture(t, evidence))
			if err != nil {
				t.Fatal(err)
			}
			peers := rollingPeerNoncesFixture(t, manager.contract, prepared)
			if stop == "cleanup" {
				if _, err = e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
					t.Fatal(err)
				}
			} else {
				_, resolver, err := keys.rollingDependencies()
				if err != nil {
					t.Fatal(err)
				}
				keys.bindRollingJournal(rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(time.Hour)}, resolver)
			}
			if _, err = e.svc.signRollingRenewalTree(t.Context(), manager, id, peers); err == nil {
				t.Fatal("closed session produced partials")
			}
			record, err := manager.operation(t.Context(), id)
			if err != nil || record.Events["tree_signed"].Evidence != "" {
				t.Fatal("closed session retained new signatures", err)
			}
		})
	}
}

func TestRollingDelegateDerivationAndExactParity(t *testing.T) {
	_, manager, keys, _, _ := rollingApplicationFixture(t)
	scope := rollingKeyContext{vault: fixture.VaultID, network: "mainnet", operator: manager.contract.Keys.Operator.SerializeCompressed()}
	pub, err := keys.rollingDelegatePublic(scope)
	if err != nil {
		t.Fatal(err)
	}
	// policy.DeriveVtxoVaultCosignerScalar deliberately returns the even lift.
	if pub.SerializeCompressed()[0] != 2 {
		t.Fatal("delegate derivation compatibility changed")
	}
	g, r, err := keys.rollingPublic(scope)
	if err != nil || pub.IsEqual(g) || pub.IsEqual(r) {
		t.Fatal("delegate key scope reused", err)
	}
	for _, change := range []string{"vault", "network", "operator"} {
		altered := scope
		switch change {
		case "vault":
			altered.vault = "other-vault"
		case "network":
			altered.network = "regtest"
		case "operator":
			other, _ := btcec.NewPrivateKey()
			altered.operator = other.PubKey().SerializeCompressed()
		}
		other, err := keys.rollingDelegatePublic(altered)
		if err == nil && other.IsEqual(pub) {
			t.Fatal("delegate scope collision", change)
		}
	}
	c := *manager.contract
	c.Parameters.DelegatePubkey = append([]byte(nil), pub.SerializeCompressed()...)
	c.Parameters.DelegatePubkey[0] = 3
	called := false
	err = keys.withRollingDelegate(t.Context(), policy.RollingSnapshot{Enrollment: policy.RollingEnrollment{VaultID: fixture.VaultID, Network: "mainnet"}}, &c, func(*btcec.PrivateKey) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("opposite delegate parity accepted")
	}
}

func TestRollingTreeCompletesStockMuSigAfterDatabaseAndKeyRestart(t *testing.T) {
	var operator *btcec.PrivateKey
	e, manager, keys, id, evidence := rollingFinalFixtureBuild(t, nil, false, func(key *btcec.PrivateKey) { operator = key })
	sequencePath := filepath.Join(t.TempDir(), "economic-sequence")
	sequence, err := policy.OpenMonotonic(sequencePath, testCredentialIntegrityKey)
	if err != nil {
		t.Fatal(err)
	}
	// Only the test seeds an existing fixture ledger into a new sequence file.
	if err = sequence.Observe(0); err != nil {
		t.Fatal(err)
	}
	if err = e.ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	prepared, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, rollingUnsignedTreeFixture(t, evidence))
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	graph, commitment, root, err := verifyRollingSigningTree(manager.contract, record, prepared.Tree)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := arktree.NewTreeCoordinatorSession(root, commitment.UnsignedTx.TxOut[0].Value, graph)
	if err != nil {
		t.Fatal(err)
	}
	peer := arktree.NewTreeSignerSession(operator)
	if err = peer.Init(root, commitment.UnsignedTx.TxOut[0].Value, graph); err != nil {
		t.Fatal(err)
	}
	peerNonces, err := peer.GetNonces()
	if err != nil {
		t.Fatal(err)
	}
	delegate, err := btcec.ParsePubKey(manager.contract.Parameters.DelegatePubkey)
	if err != nil {
		t.Fatal(err)
	}
	own := arktree.TreeNonces{}
	all := map[string]map[string]string{}
	for txid, raw := range prepared.Capsule.Nonces {
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		own[txid] = &arktree.Musig2Nonce{PubNonce: [66]byte(decoded)}
		all[txid] = map[string]string{hex.EncodeToString(schnorr.SerializePubKey(delegate)): raw, hex.EncodeToString(schnorr.SerializePubKey(operator.PubKey())): hex.EncodeToString(peerNonces[txid].PubNonce[:])}
	}
	coordinator.AddNonce(delegate, own)
	coordinator.AddNonce(operator.PubKey(), peerNonces)
	aggregate, err := coordinator.AggregateNonces()
	if err != nil {
		t.Fatal(err)
	}
	// No live in-memory nonce state survives this restart. The capsule and
	// immutable enrollment are recovered from the authenticated SQLite file.
	_, resolver, err := keys.rollingDependencies()
	if err != nil {
		t.Fatal(err)
	}
	reloadedMaster, _ := btcec.PrivKeyFromBytes(e.master.Serialize())
	keys.wipe()
	if err = e.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	preparedDatabase, err := os.ReadFile(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := policy.OpenLedgerForNetwork(e.dbPath, nil, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err = reopened.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	retainedSequence, err := policy.OpenMonotonic(sequencePath, testCredentialIntegrityKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.AttachMonotonic(retainedSequence); err != nil {
		t.Fatal(err)
	}
	capabilities, err := NewFileBackedKeyCapabilities(reloadedMaster, LocalSigner{Priv: e.operator})
	if err != nil {
		t.Fatal(err)
	}
	newKeys := capabilities.rollingOperation.(*fileBackedVaultKeys)
	t.Cleanup(newKeys.wipe)
	newKeys.bindRollingJournal(reopened, resolver)
	e.svc.keys.rollingOperation = newKeys
	manager.store = reopened
	restored, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, prepared.Tree)
	if err != nil || !reflect.DeepEqual(prepared, restored) {
		t.Fatal("restart replaced nonce capsule", err)
	}
	signed, err := e.svc.signRollingRenewalTree(t.Context(), manager, id, all)
	if err != nil {
		t.Fatal(err)
	}
	partials := arktree.TreePartialSigs{}
	for txid, raw := range signed.Signatures {
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		sig := &musig2.PartialSignature{}
		if err = sig.Decode(bytes.NewReader(decoded)); err != nil {
			t.Fatal(err)
		}
		partials[txid] = sig
	}
	if _, err = coordinator.AddSignatures(delegate, partials); err != nil {
		t.Fatal(err)
	}
	peer.SetAggregatedNonces(aggregate)
	peerSigs, err := peer.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.AddSignatures(operator.PubKey(), peerSigs); err != nil {
		t.Fatal(err)
	}
	complete, err := coordinator.SignTree()
	if err != nil {
		t.Fatal(err)
	}
	if err = arktree.ValidateTreeSigs(root, commitment.UnsignedTx.TxOut[0].Value, complete); err != nil {
		t.Fatal("restarted delegate produced invalid recovery", err)
	}
	evidence.VtxoTree, err = complete.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.svc.prepareRollingFinal(t.Context(), manager, id, evidence); err != nil {
		t.Fatal("completed recovery could not authorize final", err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(e.dbPath, preparedDatabase, 0600); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := policy.OpenLedgerForNetwork(e.dbPath, nil, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rolledBack.Close() })
	if err = rolledBack.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	if err = rolledBack.AttachMonotonic(retainedSequence); err == nil {
		t.Fatal("database rollback concealed consumed nonces")
	}
	newKeys.bindRollingJournal(rolledBack, resolver)
	if _, err = newKeys.signRollingTree(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("rolled-back signing journal opened nonce capsule")
	}
}

type rollingTreeResponseMutation struct {
	rollingOperationAuthorizer
	prepare   func(*rollingPreparedTree)
	afterSign func()
}

func (k rollingTreeResponseMutation) prepareRollingTree(ctx context.Context, vault, id string) (rollingPreparedTree, error) {
	prepared, err := k.rollingOperationAuthorizer.prepareRollingTree(ctx, vault, id)
	if err == nil && k.prepare != nil {
		k.prepare(&prepared)
	}
	return prepared, err
}

func (k rollingTreeResponseMutation) signRollingTree(ctx context.Context, vault, id string) (rollingSignedTree, error) {
	signed, err := k.rollingOperationAuthorizer.signRollingTree(ctx, vault, id)
	if err == nil && k.afterSign != nil {
		k.afterSign()
	}
	return signed, err
}

func TestRollingTreeRejectsMalformedKeyResponseBeforeNonceRelease(t *testing.T) {
	for _, mutation := range []string{"coverage", "point", "iv", "ciphertext"} {
		t.Run(mutation, func(t *testing.T) {
			e, manager, keys, id, evidence := rollingFinalFixtureBuild(t, nil, false)
			e.svc.keys.rollingOperation = rollingTreeResponseMutation{rollingOperationAuthorizer: keys, prepare: func(p *rollingPreparedTree) {
				switch mutation {
				case "coverage":
					for txid := range p.Capsule.Nonces {
						delete(p.Capsule.Nonces, txid)
						break
					}
				case "point":
					for txid := range p.Capsule.Nonces {
						p.Capsule.Nonces[txid] = hex.EncodeToString(make([]byte, 66))
						break
					}
				case "iv":
					p.Capsule.IV = "00"
				case "ciphertext":
					p.Capsule.Ciphertext = "00"
				}
			}}
			if _, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, rollingUnsignedTreeFixture(t, evidence)); err == nil {
				t.Fatal("bad nonce response released")
			}
			record, err := manager.operation(t.Context(), id)
			if err != nil || record.Events["tree_prepared"].Evidence != "" {
				t.Fatal("bad nonce response retained", err)
			}
		})
	}
}

func TestRollingTreeCleanupDuringSigningSuppressesResponse(t *testing.T) {
	e, manager, keys, id, evidence := rollingFinalFixtureBuild(t, nil, false)
	prepared, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, rollingUnsignedTreeFixture(t, evidence))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.keys.rollingOperation = rollingTreeResponseMutation{rollingOperationAuthorizer: keys, afterSign: func() {
		if _, err := e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err = e.svc.signRollingRenewalTree(t.Context(), manager, id, rollingPeerNoncesFixture(t, manager.contract, prepared)); err == nil {
		t.Fatal("cleanup raced past signature retention")
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["tree_signed"].Evidence != "" || record.Events["cleanup_pending"].Evidence == "" {
		t.Fatal("cleanup/signing race lost fence", err)
	}
	if _, err = keys.authorizeRollingFinal(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("cleanup race granted final authority")
	}
}

func TestRollingTreeConcurrentPreparationAndPeerChallenges(t *testing.T) {
	e, manager, _, id, evidence := rollingFinalFixtureBuild(t, nil, false)
	tree := rollingUnsignedTreeFixture(t, evidence)
	var wg sync.WaitGroup
	start := make(chan struct{})
	preparedResults := make(chan rollingPreparedTree, 4)
	for range 4 {
		wg.Go(func() {
			<-start
			p, err := e.svc.prepareRollingRenewalTree(t.Context(), manager, id, tree)
			if err == nil {
				preparedResults <- p
			}
		})
	}
	close(start)
	wg.Wait()
	close(preparedResults)
	var prepared rollingPreparedTree
	for p := range preparedResults {
		if prepared.Binding.BatchID != "" && !reflect.DeepEqual(prepared, p) {
			t.Fatal("multiple nonce capsules released")
		}
		prepared = p
	}
	if prepared.Binding.BatchID == "" {
		t.Fatal("no prepared session")
	}
	peersA := rollingPeerNoncesFixture(t, manager.contract, prepared)
	peersB := rollingPeerNoncesFixture(t, manager.contract, prepared)
	start = make(chan struct{})
	errors := make(chan error, 2)
	for _, peers := range []map[string]map[string]string{peersA, peersB} {
		wg.Go(func() {
			<-start
			_, err := e.svc.signRollingRenewalTree(t.Context(), manager, id, peers)
			errors <- err
		})
	}
	close(start)
	wg.Wait()
	close(errors)
	success := 0
	for err := range errors {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("different challenges did not have exactly one winner", success)
	}
}
