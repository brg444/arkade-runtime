package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/brg444/arkade-runtime/internal/ports"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type delegatedFixture struct {
	f        spendingRenewalProofFixture
	p        lightDelegationPlan
	tree     lightDelegationTree
	final    lightRenewalFinalEvidence
	operator *btcec.PrivateKey
	guardian *btcec.PrivateKey
	now      *time.Time
}

func newDelegatedFixture(t *testing.T, otherSessions ...*btcec.PrivateKey) delegatedFixture {
	t.Helper()
	return newDelegatedFixtureForAccount(t, "mutinynet", "light", otherSessions...)
}
func newDelegatedFixtureForAccount(t *testing.T, network, tier string, otherSessions ...*btcec.PrivateKey) delegatedFixture {
	t.Helper()
	f := newSpendingRenewalProofFixtureForAccount(t, network, tier)
	f.env.svc.LightDelegationEnabled = true
	keys := f.env.svc.keys.lightDelegation.(*fileBackedVaultKeys)
	var guardian *btcec.PrivateKey
	if err := keys.withRenewalKey(context.Background(), f.contract, func(key *btcec.PrivateKey) error { guardian, _ = btcec.PrivKeyFromBytes(key.Serialize()); return nil }); err != nil {
		t.Fatal(err)
	}
	operator, _ := btcec.NewPrivateKey()
	f, _, final := buildSpendingRenewalFinalFixture(t, f, guardian, operator, otherSessions...)
	now := time.Now().UTC().Truncate(time.Second)
	valid := now.Add(time.Hour).Unix()
	expires := now.Add(2 * time.Hour).Unix()
	f.message, _ = (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, ValidAt: valid, ExpireAt: expires, CosignersPublicKeys: []string{"02" + f.contract.Binding.CosignerPub}}).Encode()
	proof, _ := f.proof(t).B64Encode()
	partial, err := parsePSBT(final.OwnerForfeitPSBT)
	if err != nil {
		t.Fatal(err)
	}
	partial.UnsignedTx.TxIn = partial.UnsignedTx.TxIn[:1]
	partial.Inputs = partial.Inputs[:1]
	partial.Inputs[0].TaprootScriptSpendSig = nil
	partial.Inputs[0].SighashType = delegatedOwnerSighash
	signature, err := signTapLeafAtWithSighash(partial, 0, f.owner, f.tree.SpendLeaf, delegatedOwnerSighash)
	if err != nil {
		t.Fatal(err)
	}
	partial.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{signature}
	forfeit, _ := partial.B64Encode()
	r := lightDelegationRequest{Program: f.contract.Binding.Program, DescriptorHash: f.contract.DescriptorHash, VaultID: f.contract.Binding.VaultID, OperationID: f.plan.OperationID, Intent: lightDelegateIntent{proof, f.message}, ForfeitTxs: []string{forfeit}, DeleteIntent: delegatedDeleteFixture(t, f), ExpiresAt: expires}
	digest, _ := lightDelegationRequestDigest(r)
	ownerSig, err := schnorr.Sign(f.owner, digest)
	if err != nil {
		t.Fatal(err)
	}
	r.OwnerSignature = hex.EncodeToString(ownerSig.Serialize())
	script, err := delegationForfeitScript(f.contract.Binding.Network)
	if err != nil {
		t.Fatal(err)
	}
	p, err := verifyDelegationRequest(r, f.contract, script)
	if err != nil {
		t.Fatal(err)
	}
	p.InputExpiresAt = now.Add(24 * time.Hour).Unix()
	unsigned := append(arktree.FlatTxTree(nil), final.VtxoTree...)
	for i := range unsigned {
		tx, err := parsePSBT(unsigned[i].Tx)
		if err != nil {
			t.Fatal(err)
		}
		tx.Inputs[0].TaprootKeySpendSig = nil
		unsigned[i].Tx, _ = tx.B64Encode()
	}
	unsigned, _, err = canonicalLightRenewalTree(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	fixture := delegatedFixture{f, p, lightDelegationTree{final.BatchID, final.BatchExpiry, final.CommitmentPSBT, unsigned}, final, operator, guardian, &now}
	expiry := p.InputExpiresAt
	f.env.svc.ArkResolver = stubArkResolver{network: f.contract.Binding.Network, signer: f.tree.ArkdPub.SerializeCompressed(), feePolicy: ports.IntentFeePolicy{OffchainInput: "100.0"}, vtxos: []ports.ResolvedVtxo{{Txid: p.Renewal.Txid, Vout: p.Renewal.Vout, ValueSats: uint64(p.Renewal.ValueSats), Script: f.tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{strings.Repeat("aa", 32)}}}}
	reopenDelegatedFixture(t, fixture)
	return fixture
}
func TestSpendingDelegationNativeMuSigAndRecovery(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		for _, tier := range []string{"light", "standard", "advanced"} {
			t.Run(network+"/"+tier, func(t *testing.T) {
				assertSpendingDelegationNativeMuSigAndRecovery(t, newDelegatedFixtureForAccount(t, network, tier))
			})
		}
	}
}
func assertSpendingDelegationNativeMuSigAndRecovery(t *testing.T, fixture delegatedFixture) {
	t.Helper()
	f, p := fixture.f, fixture.p
	keys := f.env.svc.keys.lightDelegation
	capsule, err := keys.prepareSpendingDelegationTree(t.Context(), f.contract, p, fixture.tree)
	if err != nil {
		t.Fatal(err)
	}
	graph, commitment, root, err := verifyRenewalSigningTree(f.contract, p, fixture.tree)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := arktree.NewTreeCoordinatorSession(root, commitment.UnsignedTx.TxOut[0].Value, graph)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := arktree.NewTreeNonces(capsule.Nonces)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.AddNonce(fixture.guardian.PubKey(), ours)
	operator := arktree.NewTreeSignerSession(fixture.operator)
	if err := operator.Init(root, commitment.UnsignedTx.TxOut[0].Value, graph); err != nil {
		t.Fatal(err)
	}
	peer, err := operator.GetNonces()
	if err != nil {
		t.Fatal(err)
	}
	coordinator.AddNonce(fixture.operator.PubKey(), peer)
	all := map[string]map[string]string{}
	for txid, n := range ours {
		all[txid] = map[string]string{f.contract.Binding.CosignerPub: hex.EncodeToString(n.PubNonce[:]), hex.EncodeToString(schnorr.SerializePubKey(fixture.operator.PubKey())): hex.EncodeToString(peer[txid].PubNonce[:])}
	}
	prepared := lightDelegationPreparedTree{fixture.tree, capsule}
	bindDelegationTestTranscript(t, fixture, prepared, all)
	sigs, err := keys.signSpendingDelegationTree(t.Context(), f.contract, p, prepared, all)
	if err != nil {
		t.Fatal(err)
	}
	reopenDelegatedFixture(t, fixture)
	keys = f.env.svc.keys.lightDelegation
	replay, err := keys.signSpendingDelegationTree(t.Context(), f.contract, p, prepared, all)
	if err != nil || !sameDelegationBytes(sigs, replay) {
		t.Fatal("nonce capsule restart changed signature", err)
	}
	changedPeers := map[string]map[string]string{}
	for txid, peers := range all {
		copyPeers := map[string]string{}
		for key, nonce := range peers {
			copyPeers[key] = nonce
		}
		copyPeers[hex.EncodeToString(schnorr.SerializePubKey(fixture.operator.PubKey()))] = capsule.Nonces[txid]
		changedPeers[txid] = copyPeers
	}
	if _, err := keys.signSpendingDelegationTree(t.Context(), f.contract, p, prepared, changedPeers); err == nil {
		t.Fatal("second peer transcript reused nonce after restart")
	}
	oursigs, err := arktree.NewTreePartialSigs(sigs)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := coordinator.AggregateNonces()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.AddSignatures(fixture.guardian.PubKey(), oursigs); err != nil {
		t.Fatal("native Guardian partial signature", err)
	}
	operator.SetAggregatedNonces(aggregate)
	peerSigs, err := operator.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.AddSignatures(fixture.operator.PubKey(), peerSigs); err != nil {
		t.Fatal(err)
	}
	signed, err := coordinator.SignTree()
	if err != nil {
		t.Fatal(err)
	}
	if err := arktree.ValidateTreeSigs(root, commitment.UnsignedTx.TxOut[0].Value, signed); err != nil {
		t.Fatal(err)
	}
	flat, _ := signed.Serialize()
	final, err := f.env.svc.prepareSpendingDelegationFinal(t.Context(), p, f.contract, prepared, fixture.final.CommitmentPSBT, flat, fixture.final.Connectors)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := parsePSBT(final.SignedForfeit)
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range packet.Inputs[0].TaprootScriptSpendSig {
		if err := verifySchnorrOnInputWithSighash(packet, 0, signature.Signature, signature.XOnlyPubKey, f.tree.SpendLeaf, signature.SigHash); err != nil {
			t.Fatal(err)
		}
	}
	if len(packet.Inputs[0].TaprootScriptSpendSig) != 2 {
		t.Fatal("both owner and Guardian required")
	}
	changed := prepared
	changed.Capsule.Binding = "00" + changed.Capsule.Binding[2:]
	if _, err := keys.signSpendingDelegationTree(t.Context(), f.contract, p, changed, all); err == nil {
		t.Fatal("changed nonce binding signed")
	}
	unsignedFinal := final.Evidence
	unsignedFinal.VtxoTree = fixture.tree.VtxoTree
	if _, err := keys.authorizeSpendingDelegation(t.Context(), f.contract, p, &unsignedFinal); err == nil {
		t.Fatal("unsigned replacement authorized")
	}
	if path := os.Getenv("VAULT_DELEGATION_PUBLIC_FIXTURE"); path != "" {
		raw, _ := json.MarshalIndent(struct {
			Descriptor any                      `json:"descriptor"`
			Plan       lightDelegationPlan      `json:"plan"`
			Recovery   *lightDelegationRecovery `json:"recovery"`
		}{f.contract, p, delegationRecoveryWire(final.Evidence)}, "", "  ")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestSpendingDelegationNonceCapsuleRejectsWrongWalletAndTamper(t *testing.T) {
	a := newDelegatedFixture(t)
	b := newDelegatedFixture(t)
	keys := a.f.env.svc.keys.lightDelegation
	capsule, err := keys.prepareSpendingDelegationTree(t.Context(), a.f.contract, a.p, a.tree)
	if err != nil {
		t.Fatal(err)
	}
	prepared := lightDelegationPreparedTree{a.tree, capsule}
	if _, err := b.f.env.svc.keys.lightDelegation.signSpendingDelegationTree(t.Context(), b.f.contract, b.p, prepared, nil); err == nil {
		t.Fatal("cross-wallet capsule accepted")
	}
	raw, _ := hex.DecodeString(capsule.Ciphertext)
	raw[0] ^= 1
	prepared.Capsule.Ciphertext = hex.EncodeToString(raw)
	if _, err := keys.signSpendingDelegationTree(t.Context(), a.f.contract, a.p, prepared, nil); err == nil {
		t.Fatal("tampered capsule accepted")
	}
	if bytes.Contains(raw, a.guardian.Serialize()) {
		t.Fatal("plaintext signing key in capsule")
	}
}

func bindDelegationTestTranscript(t *testing.T, fixture delegatedFixture, prepared lightDelegationPreparedTree, all map[string]map[string]string) {
	t.Helper()
	s, p := fixture.f.env.svc, fixture.p
	if _, err := s.scheduleSpendingDelegationSet(t.Context(), delegatedSetFixture(t, fixture, 7)); err != nil {
		t.Fatal(err)
	}
	*fixture.now = time.Unix(p.ValidAt, 0)
	for _, phase := range []string{"claimed", "register_authorized", "register_dispatched", "register_result", "batch_started", "tree_prepared", "nonces_committed"} {
		var evidence any = struct{}{}
		if phase == "tree_prepared" {
			evidence = prepared
		}
		if phase == "nonces_committed" {
			evidence = all
		}
		raw, _ := json.Marshal(evidence)
		if _, err := s.Stores.LightDelegation.AdvanceLightDelegation(t.Context(), policy.LightDelegationEvent{OperationID: p.Request.OperationID, Phase: phase, Evidence: string(raw)}, 100000); err != nil {
			t.Fatal(phase, err)
		}
	}
}

func reopenDelegatedFixture(t *testing.T, f delegatedFixture) {
	t.Helper()
	e := f.f.env
	if err := e.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := policy.OpenLedgerForNetwork(e.dbPath, func() time.Time { return *f.now }, f.f.contract.Binding.Network)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	e.ledger = ledger
	e.svc.Stores = testStores(t, ledger)
	oldKeys := e.svc.keys.lightDelegation.(*fileBackedVaultKeys)
	var master *btcec.PrivateKey
	if err := oldKeys.withMaster(func(key *btcec.PrivateKey) error { master, _ = btcec.PrivKeyFromBytes(key.Serialize()); return nil }); err != nil {
		t.Fatal(err)
	}
	newKeys := &fileBackedVaultKeys{master: master}
	newKeys.bindDelegationJournal(ledger)
	e.svc.keys.lightDelegation = newKeys
	t.Cleanup(newKeys.wipe)
	e.svc.SessionNow = func() time.Time { return *f.now }
}

func delegatedDeleteFixture(t *testing.T, f spendingRenewalProofFixture) lightDelegateIntent {
	t.Helper()
	message, err := (intent.DeleteMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: 0}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := chainhash.NewHashFromStr(f.plan.Txid)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := intent.New(message, []intent.Input{{OutPoint: &wire.OutPoint{Hash: *hash, Index: f.plan.Vout}, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: &wire.TxOut{Value: f.plan.ValueSats, PkScript: f.tree.PkScript}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{ControlBlock: f.tree.SpendControl, Script: f.tree.SpendLeaf, LeafVersion: txscript.BaseLeafVersion}}
		if i == 1 {
			if err := txutils.SetArkPsbtField(&proof.Packet, i, txutils.VtxoTaprootTreeField, txutils.TapTree(f.tree.RevealedScripts)); err != nil {
				t.Fatal(err)
			}
		}
		sig, err := signTapLeafAtWithSighash(&proof.Packet, i, f.owner, f.tree.SpendLeaf, txscript.SigHashAll)
		if err != nil {
			t.Fatal(err)
		}
		proof.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	}
	raw, err := proof.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return lightDelegateIntent{raw, message}
}

func delegatedSetFixture(t *testing.T, f delegatedFixture, count uint32) spendingDelegationSetRequest {
	t.Helper()
	r := f.p.Request
	set := spendingDelegationSetRequest{Program: r.Program, DescriptorHash: r.DescriptorHash, VaultID: r.VaultID, SetID: r.OperationID, Plans: []spendingDelegationInput{{OperationID: r.OperationID, Intent: r.Intent, ForfeitTxs: r.ForfeitTxs, DeleteIntent: r.DeleteIntent, ExpiresAt: r.ExpiresAt, OwnerSignature: r.OwnerSignature}}}
	signSpendingSetFixture(t, f.f.env, &set, count)
	return set
}
