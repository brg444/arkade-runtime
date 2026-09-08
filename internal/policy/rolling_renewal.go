package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

// These are persisted stages of one exact registration, not permissions to
// sign arbitrary caller-supplied trees or forfeits. The application verifies
// each transcript before committing it and the key backend reads it again.
var rollingRenewalPredecessors = map[string]string{
	"register_dispatched": "authorized",
	"registered":          "register_dispatched",
	"tree_requested":      "registered",
	"tree_prepared":       "tree_requested",
	"nonces_committed":    "tree_prepared",
	"tree_signed":         "nonces_committed",
	"final_authorized":    "tree_signed",
	"final_signed":        "final_authorized",
	"cleanup_pending":     "authorized",
	"cleanup_authorized":  "cleanup_pending",
	"cleanup_dispatched":  "cleanup_authorized",
	"cleanup_result":      "cleanup_dispatched",
}

type RollingCleanupDeadline struct {
	ExpiresAt int64 `json:"expiresAt"`
}

// BeginRollingCleanup fences final signing before any deletion signature is
// created. The service clock sets the proof deadline exactly once. A deadline
// or deletion acknowledgement never releases an uncertain controller fence.
func (l *Ledger) BeginRollingCleanup(ctx context.Context, operationID string) (RollingEvent, error) {
	return l.appendRollingEvent(ctx, RollingEvent{OperationID: operationID, Phase: "cleanup_pending"}, nil, 0, false)
}

func rollingCleanupDeadline(e RollingEvent) (RollingCleanupDeadline, error) {
	var d RollingCleanupDeadline
	if e.Phase != "cleanup_pending" || json.Unmarshal([]byte(e.Evidence), &d) != nil {
		return d, fmt.Errorf("rolling cleanup deadline missing")
	}
	created, err := rollingTime(e.CreatedAt)
	canonical, encodeErr := json.Marshal(d)
	if err != nil || encodeErr != nil || string(canonical) != e.Evidence || d.ExpiresAt != created.Unix()+rolling.CleanupLifetimeSeconds-1 {
		return d, fmt.Errorf("rolling cleanup deadline binding")
	}
	return d, nil
}

func validateRollingRenewalLifecycle(s *RollingSnapshot) error {
	_, cleanup := s.Events["cleanup_pending"]
	_, finalAuthority := s.Events["final_authorized"]
	if cleanup && finalAuthority {
		return fmt.Errorf("rolling final authority and cleanup conflict")
	}
	for phase, predecessor := range rollingRenewalPredecessors {
		e, exists := s.Events[phase]
		if !exists {
			continue
		}
		if s.Operation.Proposal.Kind != rolling.RenewalOperation {
			return fmt.Errorf("renewal stage on a native operation")
		}
		prior, ok := s.Events[predecessor]
		if !ok {
			return fmt.Errorf("rolling %s requires %s", phase, predecessor)
		}
		at, err := rollingTime(e.CreatedAt)
		before, priorErr := rollingTime(prior.CreatedAt)
		if err != nil || priorErr != nil || at.Before(before) {
			return fmt.Errorf("rolling renewal stage time moved backward")
		}
	}
	if cleanup {
		cleanupAt, _ := rollingTime(s.Events["cleanup_pending"].CreatedAt)
		for phase := range rollingRenewalPredecessors {
			if phase == "cleanup_pending" || phase == "cleanup_authorized" || phase == "cleanup_dispatched" || phase == "cleanup_result" {
				continue
			}
			if event, ok := s.Events[phase]; ok {
				at, err := rollingTime(event.CreatedAt)
				if err != nil || at.After(cleanupAt) {
					return fmt.Errorf("rolling stage follows cleanup fence")
				}
			}
		}
		if _, err := rollingCleanupDeadline(s.Events["cleanup_pending"]); err != nil {
			return err
		}
		// Earlier tree work may remain as evidence, but no new tree/final stage
		// can be appended after cleanup starts (enforced in the mutation too).
		for _, phase := range []string{"submitted", "finalized", "aborted"} {
			if _, ok := s.Events[phase]; ok {
				return fmt.Errorf("rolling cleanup remains unresolved")
			}
		}
	}
	if s.Operation.Proposal.Kind == rolling.RenewalOperation {
		if submitted, ok := s.Events["submitted"]; ok {
			signed, signedOK := s.Events["final_signed"]
			if !finalAuthority || !signedOK {
				return fmt.Errorf("rolling renewal requires retained final signatures")
			}
			at, err := rollingTime(submitted.CreatedAt)
			before, priorErr := rollingTime(signed.CreatedAt)
			if err != nil || priorErr != nil || at.Before(before) {
				return fmt.Errorf("rolling submission predates final authority")
			}
		}
	}
	return nil
}
