package policy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReviewerIndependentHandlesCannotOversubscribeRecipientPlusFee combines
// the cross-process reservation boundary with the v1 economic-outflow rule.
// Recipient-only accounting would allow both 51-sat outflows through a
// 100-sat allowance because each recipient is only 45 sats.
func TestReviewerIndependentHandlesCannotOversubscribeRecipientPlusFee(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-outflow.sqlite")
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	ledgers := make([]*Ledger, 2)
	for i := range ledgers {
		ledger, err := OpenLedger(path, clock.Now)
		if err != nil {
			t.Fatalf("open ledger %d: %v", i, err)
		}
		if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
			t.Fatalf("integrity key %d: %v", i, err)
		}
		ledgers[i] = ledger
		cleanupLedger := ledger
		t.Cleanup(func() { _ = cleanupLedger.Close() })
	}

	start := make(chan struct{})
	results := make(chan error, len(ledgers))
	var wg sync.WaitGroup
	var signerCalls atomic.Int32
	for i, ledger := range ledgers {
		wg.Add(1)
		go func(i int, ledger *Ledger) {
			defer wg.Done()
			<-start
			_, _, err := ledger.Issue(
				context.Background(), "vault-a", digest(byte(0xc0+i)),
				45, 6, 100,
				func(context.Context) (string, error) {
					signerCalls.Add(1)
					return "signed", nil
				},
			)
			results <- err
		}(i, ledger)
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case strings.Contains(err.Error(), "allowance"):
			rejected++
		default:
			t.Fatalf("issuance failed for a non-policy reason: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("results: %d succeeded and %d rejected, want one of each", succeeded, rejected)
	}
	if got := signerCalls.Load(); got != 1 {
		t.Fatalf("external signer calls = %d, want 1", got)
	}
	spent, err := ledgers[0].SpentInPeriod(
		context.Background(), "vault-a", ledgers[0].PeriodStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if spent != 51 {
		t.Fatalf("reserved outflow = %d, want 51 recipient-plus-fee sats", spent)
	}
}

// TestReviewerAmbiguousFullOutflowSurvivesRestart verifies that an uncertain
// signer result is not merely process-local state. It must remain reserved
// after reopening SQLite and must constrain a different digest as well as
// blocking a same-digest re-sign.
func TestReviewerAmbiguousFullOutflowSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ambiguous-restart.sqlite")
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	ledger, err := OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	d := digest(0xd0)
	if _, _, err := ledger.Issue(
		context.Background(), "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) {
			return "", context.DeadlineExceeded
		},
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ambiguous issuance error = %v, want deadline exceeded", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err = OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	spent, err := ledger.SpentInPeriod(context.Background(), "vault-a", ledger.PeriodStart())
	if err != nil {
		t.Fatal(err)
	}
	if spent != 77 {
		t.Fatalf("outflow after restart = %d, want durable 77-sat reservation", spent)
	}

	var signerCalls atomic.Int32
	sign := func(context.Context) (string, error) {
		signerCalls.Add(1)
		return "must-not-sign", nil
	}
	if _, _, err := ledger.Issue(context.Background(), "vault-a", d, 75, 2, 100, sign); err == nil {
		t.Fatal("same digest was re-signed after restart")
	}
	if _, _, err := ledger.Issue(context.Background(), "vault-a", digest(0xd1), 24, 0, 100, sign); err == nil {
		t.Fatal("different digest exceeded allowance after ambiguous outflow")
	}
	if got := signerCalls.Load(); got != 0 {
		t.Fatalf("rejected requests reached signer %d times", got)
	}
}
