package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type delegatedTestOperator struct {
	f                                                            delegatedFixture
	channel                                                      chan lightDelegationEvent
	deleteError, registerError, errorFinal                       error
	deletes, registers, finals, acks, nonceCalls, signatureCalls int
	submitted                                                    []string
	coordinator                                                  arktree.CoordinatorSession
	peer                                                         arktree.SignerSession
	resolver                                                     *lightRenewalSettledResolver
	stopAt                                                       string
}

func (o *delegatedTestOperator) deleteIntent(_ context.Context, proof, message string) error {
	o.deletes++
	packet, err := parsePSBT(proof)
	if err != nil {
		return err
	}
	if len(packet.UnsignedTx.TxOut) != 1 || packet.UnsignedTx.TxOut[0].Value != 0 {
		return fmt.Errorf("delete transfers value")
	}
	for i, input := range packet.Inputs {
		if len(input.TaprootScriptSpendSig) != 2 {
			return fmt.Errorf("delete incomplete signatures")
		}
		for _, sig := range input.TaprootScriptSpendSig {
			if err := verifySchnorrOnInputWithSighash(packet, i, sig.Signature, sig.XOnlyPubKey, o.f.f.tree.SpendLeaf, sig.SigHash); err != nil {
				return err
			}
		}
	}
	return o.deleteError
}
func (o *delegatedTestOperator) events(context.Context, []string) (<-chan lightDelegationEvent, <-chan error, error) {
	o.channel = make(chan lightDelegationEvent, 128)
	o.channel <- lightDelegationEvent{StreamStarted: json.RawMessage(`{}`)}
	return o.channel, nil, nil
}
func (o *delegatedTestOperator) registerIntent(ctx context.Context, proof, message string) (string, error) {
	o.registers++
	if o.registerError != nil {
		return "", o.registerError
	}
	if o.stopAt == "registered" {
		return "intent-id", nil
	}
	hash := sha256.Sum256([]byte("intent-id"))
	id := o.f.tree.BatchID
	o.channel <- lightDelegationEvent{BatchStarted: &delegationBatchStarted{id, []string{hex.EncodeToString(hash[:])}, json.Number(fmt.Sprint(o.f.tree.BatchExpiry))}}
	for _, node := range o.f.tree.VtxoTree {
		o.channel <- lightDelegationEvent{TreeTx: &delegationTreeTx{id, 0, node.Txid, node.Tx, node.Children}}
	}
	o.channel <- lightDelegationEvent{TreeSigningStarted: &delegationSigningStarted{id, []string{"02" + o.f.f.descriptor.CosignerPub}, o.f.tree.CommitmentPSBT}}
	return "intent-id", nil
}
func (o *delegatedTestOperator) ack(context.Context, string) error { o.acks++; return nil }
func (o *delegatedTestOperator) nonces(ctx context.Context, batch, key string, raw map[string]string) error {
	o.nonceCalls++
	if o.stopAt == "nonces" {
		return fmt.Errorf("lost nonce response")
	}
	f := o.f
	graph, commitment, root, err := verifyDelegationSigningTree(f.f.descriptor, f.p, f.tree)
	if err != nil {
		return err
	}
	own, err := arktree.NewTreeNonces(raw)
	if err != nil {
		return err
	}
	coordinator, err := arktree.NewTreeCoordinatorSession(root, commitment.UnsignedTx.TxOut[0].Value, graph)
	if err != nil {
		return err
	}
	o.coordinator = coordinator
	coordinator.AddNonce(f.guardian.PubKey(), own)
	o.peer = arktree.NewTreeSignerSession(f.operator)
	if err := o.peer.Init(root, commitment.UnsignedTx.TxOut[0].Value, graph); err != nil {
		return err
	}
	peers, err := o.peer.GetNonces()
	if err != nil {
		return err
	}
	coordinator.AddNonce(f.operator.PubKey(), peers)
	for txid, n := range own {
		o.channel <- lightDelegationEvent{TreeNonces: &delegationTreeNonces{batch, txid, map[string]string{f.f.descriptor.CosignerPub: hex.EncodeToString(n.PubNonce[:]), hex.EncodeToString(schnorr.SerializePubKey(f.operator.PubKey())): hex.EncodeToString(peers[txid].PubNonce[:])}}}
	}
	return nil
}
func (o *delegatedTestOperator) signatures(ctx context.Context, batch, key string, raw map[string]string) error {
	o.signatureCalls++
	sigs, err := arktree.NewTreePartialSigs(raw)
	if err != nil {
		return err
	}
	aggregate, err := o.coordinator.AggregateNonces()
	if err != nil {
		return err
	}
	o.peer.SetAggregatedNonces(aggregate)
	if _, err := o.coordinator.AddSignatures(o.f.guardian.PubKey(), sigs); err != nil {
		return err
	}
	peer, err := o.peer.Sign()
	if err != nil {
		return err
	}
	if _, err := o.coordinator.AddSignatures(o.f.operator.PubKey(), peer); err != nil {
		return err
	}
	tree, err := o.coordinator.SignTree()
	if err != nil {
		return err
	}
	flat, err := tree.Serialize()
	if err != nil {
		return err
	}
	for _, node := range flat {
		packet, err := parsePSBT(node.Tx)
		if err != nil {
			return err
		}
		o.channel <- lightDelegationEvent{TreeSignature: &delegationTreeSignature{batch, node.Txid, hex.EncodeToString(packet.Inputs[0].TaprootKeySpendSig), 0}}
	}
	for _, node := range o.f.final.Connectors {
		o.channel <- lightDelegationEvent{TreeTx: &delegationTreeTx{batch, 1, node.Txid, node.Tx, node.Children}}
	}
	o.channel <- lightDelegationEvent{BatchFinalization: &delegationFinalization{batch, o.f.final.CommitmentPSBT}}
	return nil
}
func (o *delegatedTestOperator) submitLightForfeit(ctx context.Context, raw string) error {
	o.finals++
	o.submitted = append(o.submitted, raw)
	if o.errorFinal != nil {
		return o.errorFinal
	}
	o.resolver.settled = true
	o.channel <- lightDelegationEvent{BatchFinalized: &delegationBatchFinalized{o.f.tree.BatchID, "ignored-untrusted-id"}}
	return nil
}
func setupDelegatedRuntime(t *testing.T) (delegatedFixture, *delegatedTestOperator, *policy.LightDelegationSnapshot) {
	t.Helper()
	f := newDelegatedFixture(t)
	s := f.f.env.svc
	expiry := f.p.InputExpiresAt
	resolver := &lightRenewalSettledResolver{stubArkResolver: stubArkResolver{signer: s.operatorSignerPub(), feePolicy: ports.IntentFeePolicy{OffchainInput: fmt.Sprint(f.p.Renewal.FeeSats) + ".0"}, vtxos: []ports.ResolvedVtxo{{Txid: f.p.Renewal.Txid, Vout: f.p.Renewal.Vout, ValueSats: uint64(f.p.Renewal.ValueSats), Script: f.f.tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{strings.Repeat("aa", 32)}}}}}
	s.ArkResolver = resolver
	if _, err := s.scheduleLightDelegation(t.Context(), f.p.Request); err != nil {
		t.Fatal(err)
	}
	*f.now = time.Unix(f.p.ValidAt, 0)
	op := &delegatedTestOperator{f: f, resolver: resolver}
	s.lightDelegationOperatorDial = func(context.Context) (lightDelegationOperator, error) { return op, nil }
	commitment, err := parsePSBT(f.final.CommitmentPSBT)
	if err != nil {
		t.Fatal(err)
	}
	s.vaultBoardRuntime = &vaultBoardRuntime{chain: &vaultBoardTestChain{state: vaultBoardConfirmedOutpoint{ValueSats: commitment.UnsignedTx.TxOut[0].Value, PkScript: commitment.UnsignedTx.TxOut[0].PkScript, FundingBlockHash: strings.Repeat("af", 32), FundingBlockHeight: 10}}}
	saved, err := s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return f, op, saved
}
func TestLightDelegationNativeExecutorSettlesWithCompleteRecovery(t *testing.T) {
	f, op, saved := setupDelegatedRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := f.f.env.svc.executeLightDelegation(ctx, saved); err != nil {
		t.Fatal(err)
	}
	saved, err := f.f.env.svc.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.State() != "confirmed" || op.registers != 1 || op.finals != 1 || op.signatureCalls != 1 || op.acks != 1 {
		t.Fatal(saved.State(), op)
	}
	response, err := f.f.env.svc.delegationResponse(saved, f.f.descriptor, true)
	if err != nil || response.Recovery == nil || len(response.Recovery.VtxoTree) == 0 {
		t.Fatal(response, err)
	}
	raw, err := json.Marshal(response)
	if err != nil || strings.Contains(string(raw), `"Txid"`) || strings.Contains(string(raw), `"capsule"`) {
		t.Fatal("unsafe or wrong recovery wire", err)
	}
}
func TestLightDelegationLostRegistrationNeverRedispatches(t *testing.T) {
	f, op, saved := setupDelegatedRuntime(t)
	s := f.f.env.svc
	op.registerError = fmt.Errorf("lost reply")
	if err := s.executeLightDelegation(t.Context(), saved); err == nil {
		t.Fatal("lost response succeeded")
	}
	saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if saved.State() != "register_dispatched" {
		t.Fatal(saved.State())
	}
	if err := s.executeLightDelegation(t.Context(), saved); err == nil {
		t.Fatal("missing UUID accepted")
	}
	if op.registers != 1 {
		t.Fatal("duplicate registration", op.registers)
	}
	*f.now = time.Unix(f.p.Request.ExpiresAt+31, 0)
	if err := s.executeLightDelegation(t.Context(), saved); err != nil {
		t.Fatal(err)
	}
	saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if saved.State() != "expired" || op.finals != 0 {
		t.Fatal(saved.State())
	}
}
func TestLightDelegationLostFinalResponseRetriesExactBytes(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprint(accepted), func(t *testing.T) {
			f, op, saved := setupDelegatedRuntime(t)
			s := f.f.env.svc
			op.errorFinal = fmt.Errorf("lost final response")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			if err := s.executeLightDelegation(ctx, saved); err == nil {
				t.Fatal("lost response succeeded")
			}
			saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
			if saved.State() != "final_dispatched" {
				t.Fatal(saved.State())
			}
			// Old immutable authorization stays fenced even after its deadline.
			*f.now = time.Unix(f.p.Request.ExpiresAt+31, 0)
			op.errorFinal = nil
			op.resolver.settled = accepted
			if err := s.executeLightDelegation(ctx, saved); err != nil {
				t.Fatal(err)
			}
			if accepted {
				if op.finals != 1 {
					t.Fatal("resubmitted settled forfeit")
				}
			} else {
				if op.finals != 2 || op.submitted[0] != op.submitted[1] {
					t.Fatal("forfeit bytes changed", op.finals)
				}
			}
			saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
			if err := s.executeLightDelegation(ctx, saved); err != nil {
				t.Fatal(err)
			}
			saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
			if saved.State() != "confirmed" {
				t.Fatal(saved.State())
			}
		})
	}
}
func TestLightDelegationFeeDriftStopsBeforeKeyAuthority(t *testing.T) {
	f, op, saved := setupDelegatedRuntime(t)
	op.resolver.feePolicy = ports.IntentFeePolicy{OffchainInput: "200.0"}
	if err := f.f.env.svc.executeLightDelegation(t.Context(), saved); err != nil {
		t.Fatal(err)
	}
	saved, _ = f.f.env.svc.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if saved.State() != "needs_authorization" || op.registers != 0 || len(saved.Events) != 1 {
		t.Fatal(saved.State(), op.registers)
	}
}
func TestLightDelegationStopCancelsActiveStream(t *testing.T) {
	f, op, _ := setupDelegatedRuntime(t)
	op.stopAt = "registered"
	s := f.f.env.svc
	if err := s.StartLightDelegation(); err != nil {
		t.Fatal(err)
	}
	s.StopLightDelegation()
	// Idempotent shutdown must finish before ledger/key cleanup.
	s.StopLightDelegation()
}

func TestLightDelegationRestartReplaysOwnDurableTree(t *testing.T) {
	f, op, saved := setupDelegatedRuntime(t)
	s := f.f.env.svc
	op.stopAt = "nonces"
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := s.executeLightDelegation(ctx, saved); err == nil {
		t.Fatal("lost nonce response succeeded")
	}
	saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if saved.State() != "tree_prepared" {
		t.Fatal(saved.State())
	}
	capsule := saved.Events["tree_prepared"].Evidence
	reopenDelegatedFixture(t, f)
	op.stopAt = ""
	// The upstream supplies no historical events; all prior chunks and signing
	// start must come from the Guardian journal. Only replies to new submissions
	// are emitted by the simulated Operator on this new stream.
	if err := s.executeLightDelegation(ctx, saved); err != nil {
		t.Fatal(err)
	}
	saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
	if saved.State() != "confirmed" || saved.Events["tree_prepared"].Evidence != capsule || op.registers != 1 || op.nonceCalls != 2 {
		t.Fatal("restart changed session", saved.State())
	}
}

func TestLightDelegationCleanupRetainsOwnershipOnNoMatchOrLostReply(t *testing.T) {
	for _, failure := range []string{"INVALID_INTENT_PROOF: selected batch no-match", "lost successful delete response"} {
		t.Run(failure, func(t *testing.T) {
			f, op, saved := setupDelegatedRuntime(t)
			s := f.f.env.svc
			op.registerError = fmt.Errorf("lost registration UUID")
			if err := s.executeLightDelegation(t.Context(), saved); err == nil {
				t.Fatal("registration should be uncertain")
			}
			saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
			*f.now = time.Unix(f.p.Request.ExpiresAt+31, 0)
			op.deleteError = fmt.Errorf("%s", failure)
			if err := s.executeLightDelegation(t.Context(), saved); err == nil {
				t.Fatal("uncertain cleanup released")
			}
			saved, _ = s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
			if saved.State() != "cleanup_pending" || op.deletes != 1 || op.finals != 0 {
				t.Fatal(saved.State(), op.deletes)
			}
			exact := saved.Events["cleanup_authorized"].Evidence
			if _, err := s.Stores.LightDelegation.AdvanceLightDelegation(t.Context(), policy.LightDelegationEvent{OperationID: f.p.Request.OperationID, Phase: "final_authorized", Evidence: `{}`}, 0); err == nil {
				t.Fatal("cleanup raced final authority")
			}
			if err := s.executeLightDelegation(t.Context(), saved); err == nil {
				t.Fatal("retry no-match released")
			}
			held, _ := s.Stores.Allowance.SpentInPeriod(t.Context(), f.p.Request.VaultID, "")
			if held != f.p.Renewal.FeeSats {
				t.Fatal("released hold", held)
			}
			op.deleteError = nil
			if err := s.executeLightDelegation(t.Context(), saved); err != nil {
				t.Fatal(err)
			}
			terminal, _ := s.getDelegation(t.Context(), f.p.Request.VaultID, f.p.Request.OperationID)
			if terminal.State() != "expired" || terminal.Events["cleanup_authorized"].Evidence != exact {
				t.Fatal("cleanup changed", terminal.State())
			}
			// A delayed stale executor cannot resend a deletion after the generation ends.
			before := op.deletes
			if err := s.executeLightDelegation(t.Context(), saved); err == nil {
				t.Fatal("stale cleanup dispatcher not fenced")
			}
			if op.deletes != before {
				t.Fatal("stale cleanup deleted a later generation")
			}
		})
	}
}
