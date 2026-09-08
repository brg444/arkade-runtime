package application

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rollingIntentOperatorFunc func(context.Context, string, string) (string, error)

type rollingClaimCrossing struct {
	RollingOperationStore
	after func()
}

func (s rollingClaimCrossing) ClaimRollingRegistration(ctx context.Context, id string) (bool, error) {
	claimed, err := s.RollingOperationStore.ClaimRollingRegistration(ctx, id)
	if claimed && err == nil {
		s.after()
	}
	return claimed, err
}

func (f rollingIntentOperatorFunc) registerIntent(ctx context.Context, proof, message string) (string, error) {
	return f(ctx, proof, message)
}

func TestRollingRegistrationDispatchesOnceUnderConcurrentWorkers(t *testing.T) {
	e, manager, _, _, id := rollingRenewalApplicationFixture(t)
	authorizeRollingFixture(t, e, manager, id)
	emulator := rollingEmulatorFixture(t, manager, func(req rollingRegistration) (string, error) {
		return signRollingEmulatorFixture(t, manager, req), nil
	})
	proof, err := manager.prepareRegistration(t.Context(), id, emulator)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	entered, finish := make(chan struct{}), make(chan struct{})
	op := rollingIntentOperatorFunc(func(_ context.Context, raw, message string) (string, error) {
		if calls.Add(1) != 1 {
			return "", errors.New("duplicate dispatch")
		}
		close(entered)
		if raw != proof.Proof || message != proof.Message {
			t.Error("Operator received a different intent")
		}
		<-finish
		return "rolling-intent", nil
	})
	var workers sync.WaitGroup
	workers.Add(1)
	var first rollingRegisteredIntent
	var firstErr error
	go func() {
		defer workers.Done()
		first, firstErr = manager.registerRenewal(t.Context(), id, nil, op)
	}()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		close(finish)
		t.Fatal("first worker did not reach Operator")
	}
	if _, err = manager.registerRenewal(t.Context(), id, nil, op); err == nil {
		t.Error("second worker crossed pending dispatch")
	}
	close(finish)
	workers.Wait()
	if firstErr != nil || first.IntentID != "rolling-intent" || calls.Load() != 1 {
		t.Fatal("registration was not dispatched once", firstErr, calls.Load())
	}
	manager.store = rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(48 * time.Hour)}
	retry, err := manager.registerRenewal(t.Context(), id, nil, nil)
	if err != nil || retry != first || calls.Load() != 1 {
		t.Fatal("saved registration did not replay", err)
	}
}

func TestRollingRegistrationAmbiguityAndCleanupNeverRedispatch(t *testing.T) {
	for _, kind := range []string{"lost response", "empty identity", "cleanup crossing", "cleanup before send"} {
		t.Run(kind, func(t *testing.T) {
			e, manager, _, _, id := rollingRenewalApplicationFixture(t)
			authorizeRollingFixture(t, e, manager, id)
			if kind == "cleanup before send" {
				manager.store = rollingClaimCrossing{RollingOperationStore: manager.store, after: func() {
					if _, err := e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
						t.Fatal(err)
					}
				}}
			}
			emulator := rollingEmulatorFixture(t, manager, func(req rollingRegistration) (string, error) {
				return signRollingEmulatorFixture(t, manager, req), nil
			})
			calls := 0
			op := rollingIntentOperatorFunc(func(context.Context, string, string) (string, error) {
				calls++
				if kind == "lost response" {
					return "", errors.New("response unavailable")
				}
				if kind == "empty identity" {
					return "", nil
				}
				if kind == "cleanup crossing" {
					if _, err := e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
						t.Fatal(err)
					}
				}
				return "rolling-intent", nil
			})
			if _, err := manager.registerRenewal(t.Context(), id, emulator, op); err == nil {
				t.Fatal("uncertain registration reported success")
			}
			if _, err := manager.registerRenewal(t.Context(), id, nil, op); err == nil || calls != 1 {
				t.Fatal("uncertain registration retried", err, calls)
			}
			record, err := manager.operation(t.Context(), id)
			if err != nil || record.Events["register_dispatched"].Evidence == "" || record.Events["registered"].Evidence != "" || record.Events["aborted"].Phase != "" {
				t.Fatal("uncertain registration fence lost", err)
			}
		})
	}
}
