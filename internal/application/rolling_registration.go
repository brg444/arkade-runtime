package application

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

type rollingIntentOperator interface {
	registerIntent(context.Context, string, string) (string, error)
}

type rollingRegisteredIntent struct {
	IntentID string `json:"intentId"`
}

// registerRenewal is called after the batch stream subscription is ready.
// Its one-shot durable claim precedes the stock Operator call. An ambiguous
// response remains fenced for reconciliation or bounded cleanup; it never
// causes blind re-registration. The scheduler owns stream and batch handling.
func (s *RollingOperations) registerRenewal(ctx context.Context, id string, emulator *rollingEmulator, operator rollingIntentOperator) (rollingRegisteredIntent, error) {
	registration, err := s.prepareRegistration(ctx, id, emulator)
	if err != nil {
		return rollingRegisteredIntent{}, err
	}
	record, err := s.operation(ctx, id)
	if err != nil {
		return rollingRegisteredIntent{}, err
	}
	if old, ok := record.Events["registered"]; ok {
		var retained rollingRegisteredIntent
		if json.Unmarshal([]byte(old.Evidence), &retained) != nil || retained.IntentID == "" || len(retained.IntentID) > 256 {
			return rollingRegisteredIntent{}, fmt.Errorf("invalid retained rolling intent identity")
		}
		return retained, nil
	}
	if isNilInterface(operator) {
		return rollingRegisteredIntent{}, fmt.Errorf("rolling Operator required")
	}
	if err = rolling.CheckRenewalTime(registration.Message, s.store.NowUTC().Unix()); err != nil {
		return rollingRegisteredIntent{}, err
	}
	claimed, err := s.store.ClaimRollingRegistration(ctx, id)
	if err != nil {
		return rollingRegisteredIntent{}, err
	}
	if !claimed {
		return rollingRegisteredIntent{}, fmt.Errorf("rolling registration response unavailable; original intent remains fenced")
	}
	intentID, err := operator.registerIntent(ctx, registration.Proof, registration.Message)
	if err != nil {
		return rollingRegisteredIntent{}, err
	}
	if intentID == "" || len(intentID) > 256 {
		return rollingRegisteredIntent{}, fmt.Errorf("rolling Operator returned invalid intent identity")
	}
	result := rollingRegisteredIntent{IntentID: intentID}
	raw, err := json.Marshal(result)
	if err != nil {
		return rollingRegisteredIntent{}, err
	}
	if _, err = s.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "registered", Evidence: string(raw)}); err != nil {
		return rollingRegisteredIntent{}, err
	}
	return result, nil
}
