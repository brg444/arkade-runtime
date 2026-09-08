package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	arkadevaultv1 "github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

type RollingOperationStore = arkadevaultv1.RollingAllowanceStore
type rollingInputResolver interface {
	verifyRollingInputs(context.Context, *rolling.Contract, rolling.Proposal) error
}

// RollingOperations binds one enrolled vault to the journal and release-pinned
// read ports. Foreground wallet code still owns transaction submission.
type RollingOperations struct {
	store    RollingOperationStore
	vault    string
	contract *rolling.Contract
	outcomes rollingOutcomeResolver
	inputs   rollingInputResolver
}

func NewRollingOperations(store RollingOperationStore, vault string, c *rolling.Contract, resolver ports.ArkResolver) (*RollingOperations, error) {
	// Reuse the source constructor's immutable descriptor and release checks.
	source, err := NewRollingReceiptSource(store, vault, c, resolver)
	if err != nil {
		return nil, err
	}
	bound := source.(*rollingReceiptSource)
	inputs, ok := resolver.(rollingInputResolver)
	if !ok {
		return nil, fmt.Errorf("rolling input verification unavailable")
	}
	return &RollingOperations{store: store, vault: vault, contract: bound.contract, outcomes: bound.resolver, inputs: inputs}, nil
}

func (s *RollingOperations) Reserve(ctx context.Context, p rolling.Proposal) (*policy.RollingSnapshot, error) {
	if _, err := p.Rebuild(s.contract, s.store.NowUTC().Unix()); err != nil {
		return nil, err
	}
	history, err := s.store.RollingHistory(ctx, s.vault)
	if err != nil {
		return nil, err
	}
	if err := s.matchEnrollment(history.Enrollment); err != nil {
		return nil, err
	}
	if p.Transaction == nil {
		return nil, fmt.Errorf("rolling transaction required")
	}
	id := p.Transaction.TxHash().String()
	// Exact retries are resolved from the journal before requiring still-unspent
	// inputs. They cannot change the stored proposal or its allowance charge.
	records, err := s.store.RollingOperations(ctx, s.vault)
	if err != nil {
		return nil, err
	}
	for _, r := range records {
		if r.Operation.OperationID == id {
			return s.store.ReserveRolling(ctx, policy.RollingOperation{OperationID: id, VaultID: s.vault, Proposal: p}, s.contract.Parameters.Budget)
		}
	}
	if err = s.inputs.verifyRollingInputs(ctx, s.contract, p); err != nil {
		return nil, err
	}
	return s.store.ReserveRolling(ctx, policy.RollingOperation{OperationID: id, VaultID: s.vault, Proposal: p}, s.contract.Parameters.Budget)
}

func (s *RollingOperations) matchEnrollment(enrolled policy.RollingEnrollment) error {
	expected, err := rolling.EncodeDescriptor(s.contract)
	if err != nil {
		return err
	}
	if enrolled.VaultID != s.vault || !bytes.Equal(expected, []byte(enrolled.Descriptor)) {
		return fmt.Errorf("rolling enrollment mismatch")
	}
	return nil
}

func (s *RollingOperations) operation(ctx context.Context, id string) (policy.RollingSnapshot, error) {
	records, err := s.store.RollingOperations(ctx, s.vault)
	if err != nil {
		return policy.RollingSnapshot{}, err
	}
	for _, r := range records {
		if r.Operation.OperationID == id {
			if err = s.matchEnrollment(r.Enrollment); err != nil {
				return policy.RollingSnapshot{}, err
			}
			return r, nil
		}
	}
	return policy.RollingSnapshot{}, fmt.Errorf("rolling operation missing")
}

// Finalize independently verifies the outcome before recording the first
// observation. A client timestamp or assertion of completion is never used.
func (s *RollingOperations) Finalize(ctx context.Context, id, outcome string, batch *RollingBatchEvidence) (policy.RollingEvent, error) {
	record, err := s.operation(ctx, id)
	if err != nil {
		return policy.RollingEvent{}, err
	}
	if _, ok := record.Events["authorized"]; !ok {
		return policy.RollingEvent{}, fmt.Errorf("rolling operation was not authorized")
	}
	var evidence any = struct{}{}
	if record.Operation.Proposal.Kind == rolling.RenewalOperation {
		if batch == nil {
			return policy.RollingEvent{}, fmt.Errorf("renewal batch evidence required")
		}
		if err = verifyRollingRetainedBatch(s.contract, record, *batch); err != nil {
			return policy.RollingEvent{}, err
		}
		evidence = *batch
	} else if batch != nil {
		return policy.RollingEvent{}, fmt.Errorf("unexpected native batch evidence")
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return policy.RollingEvent{}, err
	}
	candidate := policy.RollingEvent{OperationID: id, Phase: "finalized", OutcomeTxid: outcome, Evidence: string(raw)}
	if old, ok := record.Events["finalized"]; ok {
		candidate.CreatedAt = old.CreatedAt
		if old != candidate {
			return policy.RollingEvent{}, fmt.Errorf("rolling finalization retry changed")
		}
		return old, nil
	}
	record.Events["finalized"] = candidate
	if err = s.outcomes.verifyRollingOutcome(ctx, s.contract, record); err != nil {
		return policy.RollingEvent{}, err
	}
	// Reconciliation may discover finalization after a lost dispatch response.
	if _, ok := record.Events["submitted"]; !ok {
		if _, err = s.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "submitted"}); err != nil {
			return policy.RollingEvent{}, err
		}
	}
	return s.store.AppendRollingEvent(ctx, candidate)
}

func (r *arkResolver) verifyRollingInputs(ctx context.Context, c *rolling.Contract, p rolling.Proposal) error {
	if len(p.Sources) < 1 || len(p.Sources) > rolling.MaxMoneyInputs+1 {
		return fmt.Errorf("rolling source count")
	}
	points := make([]string, len(p.Sources))
	for i, source := range p.Sources {
		if source.Previous == nil || int(source.Index) >= len(source.Previous.TxOut) {
			return fmt.Errorf("rolling source absent")
		}
		points[i] = source.Previous.TxHash().String() + ":" + strconv.FormatUint(uint64(source.Index), 10)
	}
	listed, err := r.listVtxosByOutpoint(ctx, points)
	if err != nil {
		return err
	}
	if len(listed) != len(points) {
		return fmt.Errorf("rolling sources not independently resolved")
	}
	byPoint := map[string]indexerVtxo{}
	for _, v := range listed {
		if v.Outpoint.Vout == nil {
			return fmt.Errorf("rolling source index absent")
		}
		point := v.Outpoint.Txid + ":" + strconv.FormatUint(uint64(*v.Outpoint.Vout), 10)
		if _, ok := byPoint[point]; ok {
			return fmt.Errorf("duplicate rolling source")
		}
		byPoint[point] = v
	}
	for i, point := range points {
		v, ok := byPoint[point]
		if !ok || v.IsSpent {
			return fmt.Errorf("rolling source is not spendable")
		}
		resolved, err := parseResolvedVtxo(v, c.PkScript)
		if err != nil {
			return err
		}
		if resolved.IsSwept || resolved.ValueSats != uint64(p.Sources[i].Previous.TxOut[p.Sources[i].Index].Value) {
			return fmt.Errorf("rolling source value or lifecycle mismatch")
		}
	}
	return nil
}
