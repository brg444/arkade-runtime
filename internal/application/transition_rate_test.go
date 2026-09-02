package application

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransitionRateLimitIsVaultScopedWithinService(t *testing.T) {
	svc := &Service{}
	for i := 0; i < maxTransitionsPerVaultPerMinute; i++ {
		if err := svc.allowTransition("vault-a"); err != nil {
			t.Fatalf("vault-a transition %d: %v", i, err)
		}
	}
	if err := svc.allowTransition("vault-a"); err == nil || err.Error() != "too many recovery signatures" {
		t.Fatalf("vault-a threshold = %v", err)
	}
	if err := svc.allowTransition("vault-b"); err != nil {
		t.Fatalf("vault-a quota affected vault-b: %v", err)
	}
}

func TestTransitionRateLimitIsServiceScoped(t *testing.T) {
	first := &Service{}
	second := &Service{}
	for i := 0; i < maxTransitionsPerVaultPerMinute; i++ {
		if err := first.allowTransition("same-vault"); err != nil {
			t.Fatalf("first service transition %d: %v", i, err)
		}
	}
	if err := first.allowTransition("same-vault"); err == nil || err.Error() != "too many recovery signatures" {
		t.Fatalf("first service threshold = %v", err)
	}
	if err := second.allowTransition("same-vault"); err != nil {
		t.Fatalf("first service quota affected second service: %v", err)
	}
}

func TestTransitionRateLimitUsesInjectedClock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc := &Service{EnrollmentNow: func() time.Time { return now }}
	for i := 0; i < maxTransitionsPerVaultPerMinute; i++ {
		if err := svc.allowTransition("vault"); err != nil {
			t.Fatalf("transition %d: %v", i, err)
		}
	}
	if err := svc.allowTransition("vault"); err == nil || err.Error() != "too many recovery signatures" {
		t.Fatalf("threshold = %v", err)
	}
	now = now.Add(transitionRateWindow)
	if err := svc.allowTransition("vault"); err != nil {
		t.Fatalf("window did not expire at the existing boundary: %v", err)
	}
}

func TestTransitionRateLimitConcurrentThreshold(t *testing.T) {
	const attempts = 64
	svc := &Service{}
	var accepted atomic.Int32
	var rejected atomic.Int32
	var unexpected atomic.Int32
	var callers sync.WaitGroup
	for range attempts {
		callers.Add(1)
		go func() {
			defer callers.Done()
			err := svc.allowTransition("same-vault")
			switch {
			case err == nil:
				accepted.Add(1)
			case err.Error() == "too many recovery signatures":
				rejected.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	callers.Wait()
	if got := accepted.Load(); got != maxTransitionsPerVaultPerMinute {
		t.Fatalf("accepted = %d, want %d", got, maxTransitionsPerVaultPerMinute)
	}
	if got := rejected.Load(); got != attempts-maxTransitionsPerVaultPerMinute {
		t.Fatalf("rejected = %d, want %d", got, attempts-maxTransitionsPerVaultPerMinute)
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("unexpected errors = %d", got)
	}
}
