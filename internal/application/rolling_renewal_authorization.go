package application

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

// The enrollment grant covers only reconstruction of a retained same-contract
// renewal. A fresh input projection must admit every source's renewal window.
func (k *fileBackedVaultKeys) authorizeRollingRenewal(ctx context.Context, vault, id string) (RollingAuthorization, error) {
	record, c, store, err := k.rollingKeyOperation(ctx, vault, id)
	if err != nil {
		return RollingAuthorization{}, err
	}
	if !record.Enrollment.AutomaticRenewal || record.Operation.Proposal.Kind != rolling.RenewalOperation {
		return RollingAuthorization{}, fmt.Errorf("immutable unattended rolling renewal grant required")
	}
	if _, cleanup := record.Events["cleanup_pending"]; cleanup {
		return RollingAuthorization{}, fmt.Errorf("rolling cleanup excludes renewal authority")
	}
	if prior, ok := record.Events["authorized"]; ok {
		var result RollingAuthorization
		if err = json.Unmarshal([]byte(prior.Evidence), &result); err != nil {
			return RollingAuthorization{}, err
		}
		if err = verifyRollingAuthorization(c, record, result); err != nil {
			return RollingAuthorization{}, err
		}
		return result, nil
	}
	_, resolver, err := k.rollingDependencies()
	if err != nil {
		return RollingAuthorization{}, err
	}
	inputs, ok := resolver.(rollingRenewalInputResolver)
	if !ok {
		return RollingAuthorization{}, fmt.Errorf("rolling renewal expiry resolution unavailable")
	}
	if err = inputs.verifyRollingRenewalInputs(ctx, c, record.Operation.Proposal, store.NowUTC().Unix()); err != nil {
		return RollingAuthorization{}, err
	}
	return k.authorizeRollingOperation(ctx, vault, id)
}

func (s *Service) authorizeAutomaticRollingRenewal(ctx context.Context, manager *RollingOperations, id string) (RollingAuthorization, error) {
	if manager == nil || isNilInterface(s.keys.rollingOperation) {
		return RollingAuthorization{}, fmt.Errorf("rolling renewal dependencies required")
	}
	record, err := manager.operation(ctx, id)
	if err != nil {
		return RollingAuthorization{}, err
	}
	if !record.Enrollment.AutomaticRenewal || record.Operation.Proposal.Kind != rolling.RenewalOperation {
		return RollingAuthorization{}, fmt.Errorf("immutable unattended rolling renewal grant required")
	}
	if err = s.requireRollingAuthorizationEnrollment(manager, record); err != nil {
		return RollingAuthorization{}, err
	}
	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	authorized, err := s.keys.rollingOperation.authorizeRollingRenewal(signCtx, manager.vault, id)
	if err != nil {
		return RollingAuthorization{}, err
	}
	if err = verifyRollingAuthorization(manager.contract, record, authorized); err != nil {
		return RollingAuthorization{}, err
	}
	raw, err := json.Marshal(authorized)
	if err != nil {
		return RollingAuthorization{}, err
	}
	retained, err := manager.store.CommitRollingRenewalAuthorization(ctx, policy.RollingEvent{OperationID: id, Phase: "authorized", Evidence: string(raw)})
	if err != nil {
		return RollingAuthorization{}, err
	}
	if err = json.Unmarshal([]byte(retained.Evidence), &authorized); err != nil {
		return RollingAuthorization{}, err
	}
	return authorized, nil
}
