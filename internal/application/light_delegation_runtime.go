package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

type lightDelegationRuntime struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	active map[string]bool
	wg     sync.WaitGroup
}

func (s *Service) StartLightDelegation() error {
	if !s.LightDelegationEnabled {
		return nil
	}
	if s.Stores.LightDelegation == nil || isNilInterface(s.keys.lightDelegation) {
		return fmt.Errorf("Light delegation execution unavailable")
	}
	if s.delegationRuntime != nil {
		return fmt.Errorf("Light delegation already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt := &lightDelegationRuntime{cancel: cancel, done: make(chan struct{}), active: map[string]bool{}}
	s.delegationRuntime = rt
	go func() {
		defer close(rt.done)
		timer := time.NewTicker(30 * time.Second)
		defer timer.Stop()
		for {
			s.dispatchDueDelegations(ctx, rt)
			select {
			case <-ctx.Done():
				rt.wg.Wait()
				return
			case <-timer.C:
			}
		}
	}()
	return nil
}
func (s *Service) StopLightDelegation() {
	if s.delegationRuntime == nil {
		return
	}
	s.delegationRuntime.cancel()
	<-s.delegationRuntime.done
}
func (s *Service) dispatchDueDelegations(ctx context.Context, rt *lightDelegationRuntime) {
	all, err := s.Stores.LightDelegation.ListLightDelegations(ctx)
	if err != nil {
		log.Printf("Light delegation journal unavailable: %v", err)
		return
	}
	for _, saved := range all {
		state := saved.State()
		if state == "confirmed" || state == "cancelled" || state == "invalidated" || state == "expired" || state == "needs_authorization" || state == "rejected" || saved.Operation.ValidAt > s.vtxoNow().Unix() {
			continue
		}
		rt.mu.Lock()
		if len(rt.active) >= 4 || rt.active[saved.Operation.VaultID] {
			rt.mu.Unlock()
			continue
		}
		rt.active[saved.Operation.VaultID] = true
		rt.wg.Add(1)
		rt.mu.Unlock()
		go func(snapshot policy.LightDelegationSnapshot) {
			defer rt.wg.Done()
			defer func() { rt.mu.Lock(); delete(rt.active, snapshot.Operation.VaultID); rt.mu.Unlock() }()
			run, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			if err := s.executeLightDelegation(run, &snapshot); err != nil && ctx.Err() == nil {
				log.Printf("Light delegation %s retained at durable phase: %v", snapshot.Operation.OperationID, err)
			}
		}(saved)
	}
}
func (s *Service) executeLightDelegation(ctx context.Context, saved *policy.LightDelegationSnapshot) error {
	c, err := s.delegationContract(saved.Operation.VaultID, saved.Operation.Program == "")
	d, tree := c.Binding, c.Tree
	if err != nil {
		return err
	}
	p, err := delegationStoredPlanForContract(saved, c)
	if err != nil {
		return err
	}
	id := saved.Operation.OperationID
	if _, cleanup := saved.Events["cleanup_pending"]; cleanup {
		return s.cleanupSpendingDelegation(ctx, saved, p, c)
	}
	if _, final := saved.Events["final_authorized"]; !final && policy.VaultBoardRegisterCanSupersede(p.Request.ExpiresAt, s.vtxoNow()) {
		v, err := s.liveRenewalInput(ctx, tree, p.Renewal.Txid, p.Renewal.Vout)
		if err != nil {
			return err
		}
		if v.ValueSats != uint64(p.Renewal.ValueSats) {
			return fmt.Errorf("Light delegation release input changed")
		}
		phase := "expired"
		if _, dispatched := saved.Events["register_dispatched"]; dispatched {
			phase = "cleanup_pending"
		}
		saved, err = s.persistDelegation(id, phase, map[string]string{"reason": "finite owner authorization ended; input live; final authorization fenced"})
		if err != nil {
			return err
		}
		if phase == "cleanup_pending" {
			return s.cleanupSpendingDelegation(ctx, saved, p, c)
		}
		return nil
	}
	if _, ok := saved.Events["final_authorized"]; ok {
		done, err := s.reconcileSpendingDelegation(ctx, saved, p, c)
		if err != nil || done {
			return err
		}
		if _, delivered := saved.Events["final_result"]; delivered {
			return nil
		}
		op, err := s.dialDelegationOperator(ctx)
		if err != nil {
			return err
		}
		// Only the immutable, already-authorized bytes are retried. An ambiguous
		// response cannot release ownership or permit a different connector.
		_, err = s.dispatchDelegationFinal(ctx, op, saved)
		return err
	}
	if _, signed := saved.Events["register_authorized"]; !signed {
		v, err := s.liveRenewalInput(ctx, tree, p.Renewal.Txid, p.Renewal.Vout)
		if err != nil {
			return err
		}
		if v.ValueSats != uint64(p.Renewal.ValueSats) || *v.ExpiresAt != p.InputExpiresAt {
			return fmt.Errorf("Light delegation input changed")
		}
		if s.vtxoNow().Unix() >= p.Request.ExpiresAt {
			_, err = s.persistDelegation(id, "expired", map[string]string{"reason": "dispatch deadline passed before signing; input still live"})
			return err
		}
		fee, _, err := s.lightRenewalFee(ctx, v, tree.PkScript, uint64(p.Renewal.ReceiverSats))
		if err != nil {
			return err
		}
		if fee != uint64(p.Renewal.FeeSats) {
			_, err = s.persistDelegation(id, "needs_authorization", map[string]string{"reason": "current Operator fee differs from signed fee"})
			return err
		}
		if _, ok := saved.Events["claimed"]; !ok {
			saved, err = s.Stores.LightDelegation.AdvanceLightDelegation(ctx, policy.LightDelegationEvent{OperationID: id, Phase: "claimed", Evidence: `{}`}, d.SpendingPolicy.PeriodAllowanceSats)
			if err != nil {
				return err
			}
		}
		signed, err := s.keys.lightDelegation.authorizeSpendingDelegation(ctx, c, p, nil)
		if err != nil {
			return err
		}
		saved, err = s.persistDelegation(id, "register_authorized", map[string]string{"psbt": signed})
		if err != nil {
			return err
		}
	}
	op, err := s.dialDelegationOperator(ctx)
	if err != nil {
		return err
	}
	topics := []string{"02" + d.CosignerPub, p.Renewal.Txid + ":" + strconv.FormatUint(uint64(p.Renewal.Vout), 10)}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, failures, err := op.events(streamCtx, topics)
	if err != nil {
		return err
	}
	// Ensure subscription is live before first registration; replayed events are
	// handled against immutable journal bindings below.
	if _, dispatched := saved.Events["register_dispatched"]; !dispatched {
		ready := false
		for !ready {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case event, ok := <-events:
				if !ok {
					return fmt.Errorf("Light delegation stream closed before registration")
				}
				ready = len(event.StreamStarted) > 0
			case err, ok := <-failures:
				if ok && err != nil {
					return err
				}
				failures = nil
			}
		}
		saved, err = s.persistDelegation(id, "register_dispatched", struct{}{})
		if err != nil {
			return err
		}
		var authorized struct {
			PSBT string `json:"psbt"`
		}
		if err := json.Unmarshal([]byte(saved.Events["register_authorized"].Evidence), &authorized); err != nil {
			return err
		}
		intentID, err := op.registerIntent(ctx, authorized.PSBT, p.Request.Intent.Message)
		if err != nil {
			if isDefiniteVaultBoardRegisterRejection(err) {
				_, persistErr := s.persistDelegation(id, "rejected", map[string]string{"reason": "first registration conclusively rejected before acceptance"})
				if persistErr != nil {
					return persistErr
				}
			}
			return err
		}
		saved, err = s.persistDelegation(id, "register_result", map[string]string{"intentId": intentID})
		if err != nil {
			return err
		}
	}
	var registration struct {
		IntentID string `json:"intentId"`
	}
	if e, ok := saved.Events["register_result"]; ok {
		if err := json.Unmarshal([]byte(e.Evidence), &registration); err != nil {
			return err
		}
	}
	if registration.IntentID == "" {
		return fmt.Errorf("registration response unavailable; original intent remains fenced")
	}
	return s.joinSpendingDelegatedBatch(ctx, op, saved, p, c, events, failures, registration.IntentID)
}
func (s *Service) dialDelegationOperator(ctx context.Context) (lightDelegationOperator, error) {
	if s.lightDelegationOperatorDial != nil {
		return s.lightDelegationOperatorDial(ctx)
	}
	o, err := dialVaultBoardOperator(ctx, s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	return o.(*stockVaultBoardOperator), nil
}
func (s *Service) joinSpendingDelegatedBatch(ctx context.Context, op lightDelegationOperator, saved *policy.LightDelegationSnapshot, p lightDelegationPlan, c renewalContract, events <-chan lightDelegationEvent, failures <-chan error, intentID string) error {
	d := c.Binding

	replayed, err := replayDelegationStream(ctx, saved, events)
	if err != nil {
		return err
	}
	events = replayed
	id := p.Request.OperationID
	batch := ""
	expiry := uint32(0)
	intentHash := sha256.Sum256([]byte(intentID))
	expectedHash := hex.EncodeToString(intentHash[:])
	var prepared lightDelegationPreparedTree
	vtxos := map[string]arktree.TxTreeNode{}
	connectors := map[string]arktree.TxTreeNode{}
	allNonces := map[string]map[string]string{}
	if event, ok := saved.Events["batch_started"]; ok {
		var start delegationBatchStarted
		if err := json.Unmarshal([]byte(event.Evidence), &start); err != nil {
			return err
		}
		batch = start.ID
		n, err := strconv.ParseUint(string(start.BatchExpiry), 10, 32)
		if err != nil {
			return err
		}
		expiry = uint32(n)
	}
	if e, ok := saved.Events["tree_prepared"]; ok {
		if err := json.Unmarshal([]byte(e.Evidence), &prepared); err != nil {
			return err
		}
		for _, node := range prepared.Tree.VtxoTree {
			vtxos[node.Txid] = node
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-failures:
			if ok && err != nil {
				return err
			}
			failures = nil
		case event, ok := <-events:
			if !ok {
				return fmt.Errorf("Light delegation event stream closed")
			}
			phase, err := delegationStreamPhase(event, batch)
			if err != nil {
				return err
			}
			if phase != "" {
				saved, err = s.persistDelegation(id, phase, event)
				if err != nil {
					return err
				}
			}
			if start := event.BatchStarted; start != nil {
				matched := false
				for _, hash := range start.IntentIDHashes {
					if hash == expectedHash {
						matched = true
					}
				}
				if !matched {
					continue
				}
				pins, err := deployment.IdentityFor(d.Network)
				n, parseErr := strconv.ParseUint(string(start.BatchExpiry), 10, 32)
				if err != nil || parseErr != nil || uint32(n) != pins.VtxoTreeExpirySeconds {
					return fmt.Errorf("Light delegation batch expiry changed")
				}
				if batch != "" && start.ID != batch {
					return fmt.Errorf("Light delegation cannot switch committed batch")
				}
				batch = start.ID
				expiry = uint32(n)
				// Store only the matched id/hash, never the unbounded unrelated membership list.
				saved, err = s.persistDelegation(id, "batch_started", delegationBatchStarted{batch, []string{expectedHash}, start.BatchExpiry})
				if err != nil {
					return err
				}
				if err := op.ack(ctx, intentID); err != nil {
					return err
				}
				continue
			}
			if tx := event.TreeTx; tx != nil {
				if tx.ID != batch || batch == "" {
					continue
				}
				target := vtxos
				if tx.BatchIndex == 1 {
					target = connectors
				} else if tx.BatchIndex != 0 {
					return fmt.Errorf("Light delegation unsupported batch index")
				}
				if len(target) >= 512 && target[tx.Txid].Txid == "" {
					return fmt.Errorf("Light delegation tree limit")
				}
				node := arktree.TxTreeNode{Txid: tx.Txid, Tx: tx.Tx, Children: tx.Children}
				if old, ok := target[tx.Txid]; ok && !sameDelegationBytes(old, node) {
					return fmt.Errorf("Light delegation tree replay changed")
				}
				target[tx.Txid] = node
				continue
			}
			if start := event.TreeSigningStarted; start != nil {
				if start.ID != batch || batch == "" {
					continue
				}
				owns := false
				for _, key := range start.Cosigners {
					if key == "02"+d.CosignerPub {
						owns = true
					}
				}
				if !owns {
					return fmt.Errorf("Light delegation tree session missing")
				}
				flat, _, err := canonicalLightRenewalTree(delegationFlat(vtxos))
				if err != nil {
					return err
				}
				unsigned := lightDelegationTree{batch, expiry, start.Commitment, flat}
				if _, ok := saved.Events["tree_prepared"]; !ok {
					capsule, err := s.keys.lightDelegation.prepareSpendingDelegationTree(ctx, c, p, unsigned)
					if err != nil {
						return err
					}
					prepared = lightDelegationPreparedTree{unsigned, capsule}
					saved, err = s.persistDelegation(id, "tree_prepared", prepared)
					if err != nil {
						return err
					}
				} else if !sameDelegationBytes(unsigned, prepared.Tree) {
					return fmt.Errorf("Light delegation committed signing tree changed")
				}
				if err := op.nonces(ctx, batch, "02"+d.CosignerPub, prepared.Capsule.Nonces); err != nil {
					return err
				}
				continue
			}
			if event.TreeNonces != nil {
				n := event.TreeNonces
				if n.ID != batch || batch == "" {
					continue
				}
				if _, ok := prepared.Capsule.Nonces[n.Txid]; !ok {
					return fmt.Errorf("Light delegation unrelated nonce")
				}
				if old, ok := allNonces[n.Txid]; ok && !sameDelegationBytes(old, n.Nonces) {
					return fmt.Errorf("Light delegation nonce replay changed")
				}
				allNonces[n.Txid] = n.Nonces
				if len(allNonces) == len(prepared.Capsule.Nonces) {
					var err error
					saved, err = s.persistDelegation(id, "nonces_committed", allNonces)
					if err != nil {
						return err
					}
					sigs := map[string]string{}
					if e, ok := saved.Events["tree_signed"]; ok {
						if err := json.Unmarshal([]byte(e.Evidence), &sigs); err != nil {
							return err
						}
					} else {
						sigs, err = s.keys.lightDelegation.signSpendingDelegationTree(ctx, c, p, prepared, allNonces)
						if err != nil {
							return err
						}
						saved, err = s.persistDelegation(id, "tree_signed", sigs)
						if err != nil {
							return err
						}
					}
					if err := op.signatures(ctx, batch, "02"+d.CosignerPub, sigs); err != nil {
						return err
					}
				}
				continue
			}
			if sig := event.TreeSignature; sig != nil {
				if sig.ID != batch || sig.BatchIndex != 0 {
					continue
				}
				node, ok := vtxos[sig.Txid]
				if !ok {
					return fmt.Errorf("Light delegation signature for unknown tree node")
				}
				packet, err := parsePSBT(node.Tx)
				if err != nil {
					return err
				}
				raw, err := hex.DecodeString(sig.Signature)
				if err != nil || len(raw) != 64 {
					return fmt.Errorf("Light delegation tree signature size")
				}
				if len(packet.Inputs[0].TaprootKeySpendSig) > 0 && !bytes.Equal(packet.Inputs[0].TaprootKeySpendSig, raw) {
					return fmt.Errorf("Light delegation tree signature changed")
				}
				packet.Inputs[0].TaprootKeySpendSig = raw
				node.Tx, err = packet.B64Encode()
				if err != nil {
					return err
				}
				vtxos[sig.Txid] = node
				continue
			}
			if final := event.BatchFinalization; final != nil {
				if final.ID != batch || batch == "" {
					continue
				}
				var err error
				if _, ok := saved.Events["final_authorized"]; !ok {
					proof, err := s.prepareSpendingDelegationFinal(ctx, p, c, prepared, final.Commitment, delegationFlat(vtxos), delegationFlat(connectors))
					if err != nil {
						return err
					}
					saved, err = s.persistDelegation(id, "final_authorized", proof)
					if err != nil {
						return err
					}
				}
				saved, err = s.dispatchDelegationFinal(ctx, op, saved)
				if err != nil {
					return err
				}
				continue
			}
			if event.BatchFinalized != nil && event.BatchFinalized.ID == batch {
				fresh, err := s.delegationContract(d.VaultID, c.legacyLight)
				if err != nil {
					return err
				}
				_, err = s.reconcileSpendingDelegation(ctx, saved, p, fresh)
				return err
			}
			if event.BatchFailed != nil && event.BatchFailed.ID == batch {
				return fmt.Errorf("Light delegation batch failed; signatures remain bound for reconciliation")
			}
		}
	}
}
func (s *Service) prepareDelegationFinal(ctx context.Context, p lightDelegationPlan, d light.Descriptor, prepared lightDelegationPreparedTree, commitment string, vtxos, connectors arktree.FlatTxTree) (lightDelegationFinal, error) {
	c, err := legacyLightRenewalContract(d, nil)
	if err != nil {
		return lightDelegationFinal{}, err
	}
	return s.prepareSpendingDelegationFinal(ctx, p, c, prepared, commitment, vtxos, connectors)
}
func (s *Service) prepareSpendingDelegationFinal(ctx context.Context, p lightDelegationPlan, c renewalContract, prepared lightDelegationPreparedTree, commitment string, vtxos, connectors arktree.FlatTxTree) (lightDelegationFinal, error) {

	var out lightDelegationFinal
	prior, err := parsePSBT(prepared.Tree.CommitmentPSBT)
	if err != nil {
		return out, err
	}
	current, err := parsePSBT(commitment)
	if err != nil || current.UnsignedTx.TxHash() != prior.UnsignedTx.TxHash() {
		return out, fmt.Errorf("Light delegation final commitment changed")
	}
	flat, graph, err := canonicalLightRenewalTree(connectors)
	if err != nil {
		return out, err
	}
	leaves := graph.Leaves()
	if len(leaves) == 0 {
		return out, fmt.Errorf("Light delegation connector missing")
	}
	connector := leaves[0]
	if len(connector.UnsignedTx.TxOut) == 0 {
		return out, fmt.Errorf("Light delegation connector output missing")
	}
	packet, err := parsePSBT(p.Request.ForfeitTxs[0])
	if err != nil {
		return out, err
	}
	packet.UnsignedTx.TxIn = append(packet.UnsignedTx.TxIn, &wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: connector.UnsignedTx.TxHash(), Index: 0}, Sequence: wire.MaxTxInSequenceNum})
	packet.Inputs = append(packet.Inputs, psbt.PInput{WitnessUtxo: connector.UnsignedTx.TxOut[0]})
	forfeit, err := packet.B64Encode()
	if err != nil {
		return out, err
	}
	evidence := lightRenewalFinalEvidence{BatchID: prepared.Tree.BatchID, BatchExpiry: prepared.Tree.BatchExpiry, CommitmentPSBT: commitment, VtxoTree: vtxos, Connectors: flat, OwnerForfeitPSBT: forfeit}
	signed, err := s.keys.lightDelegation.authorizeSpendingDelegation(ctx, c, p, &evidence)
	if err != nil {
		return out, err
	}
	return lightDelegationFinal{evidence, signed}, nil
}

func (s *Service) dispatchDelegationFinal(ctx context.Context, op lightDelegationOperator, saved *policy.LightDelegationSnapshot) (*policy.LightDelegationSnapshot, error) {
	if _, ok := saved.Events["final_result"]; ok {
		return saved, nil
	}
	var proof lightDelegationFinal
	if err := json.Unmarshal([]byte(saved.Events["final_authorized"].Evidence), &proof); err != nil {
		return nil, err
	}
	var err error
	saved, err = s.persistDelegation(saved.Operation.OperationID, "final_dispatched", struct{}{})
	if err != nil {
		return nil, err
	}
	if err := op.submitLightForfeit(ctx, proof.SignedForfeit); err != nil {
		return saved, err
	}
	return s.persistDelegation(saved.Operation.OperationID, "final_result", struct{}{})
}

func (s *Service) cleanupSpendingDelegation(ctx context.Context, saved *policy.LightDelegationSnapshot, p lightDelegationPlan, c renewalContract) error {

	id := p.Request.OperationID
	var err error
	if _, cleared := saved.Events["cleanup_result"]; cleared {
		_, err = s.persistDelegation(id, "expired", struct{}{})
		return err
	}
	if _, authorized := saved.Events["cleanup_authorized"]; !authorized {
		raw, err := s.keys.lightDelegation.authorizeSpendingDelegationDelete(ctx, c, p)
		if err != nil {
			return err
		}
		saved, err = s.persistDelegation(id, "cleanup_authorized", lightDelegateIntent{raw, p.Request.DeleteIntent.Message})
		if err != nil {
			return err
		}
	}
	var deletion lightDelegateIntent
	if err := json.Unmarshal([]byte(saved.Events["cleanup_authorized"].Evidence), &deletion); err != nil {
		return err
	}
	op, err := s.dialDelegationOperator(ctx)
	if err != nil {
		return err
	}
	saved, err = s.persistDelegation(id, "cleanup_dispatched", struct{}{})
	if err != nil {
		return err
	}
	// Delete no-match is ambiguous for intents already selected into a batch.
	// Retain ownership on every error, including a lost successful response.
	if err := op.deleteIntent(ctx, deletion.Proof, deletion.Message); err != nil {
		return err
	}
	if _, err := s.persistDelegation(id, "cleanup_result", struct{}{}); err != nil {
		return err
	}
	_, err = s.persistDelegation(id, "expired", struct{}{})
	return err
}
