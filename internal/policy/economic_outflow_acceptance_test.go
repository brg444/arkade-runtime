package policy

import (
	"context"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDailyAllowanceCountsRecipientAndFee is a release acceptance test for the
// v1 budget definition: every spend consumes recipient value plus miner fee.
// Counting only the recipient would let an attacker repeat otherwise-allowed
// small outputs and burn more than the advertised daily allowance as fees.
func TestDailyAllowanceCountsRecipientAndFee(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()

	const (
		allowance = int64(10_000)
		dust      = int64(546)
		fee       = int64(454)
	)
	var signerCalls atomic.Int32
	for i := byte(0); i < 10; i++ {
		if _, _, err := led.Issue(
			ctx, "vault-a", digest(0xa0+i), dust, fee, allowance,
			func(context.Context) (string, error) {
				signerCalls.Add(1)
				return "signed-dust-and-fee", nil
			},
		); err != nil {
			t.Fatalf("issue %d at exact cumulative outflow: %v", i+1, err)
		}
	}

	if _, _, err := led.Issue(
		ctx, "vault-a", digest(0xb0), dust, fee, allowance,
		func(context.Context) (string, error) {
			signerCalls.Add(1)
			return "must-not-sign", nil
		},
	); err == nil {
		t.Fatal("eleventh dust-plus-fee spend exceeded total-outflow allowance")
	} else if !strings.Contains(err.Error(), "allowance") {
		t.Fatalf("outflow above allowance returned non-policy error: %v", err)
	}
	if got := signerCalls.Load(); got != 10 {
		t.Fatalf("signer calls = %d, want 10; over-budget fee burn reached signer", got)
	}

	spent, err := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
	if err != nil {
		t.Fatal(err)
	}
	if spent != allowance {
		t.Fatalf("reported period outflow = %d, want recipient+fee total %d", spent, allowance)
	}
}

// TestAllowanceRejectsRecipientPlusFeeOverflow requires checked int64
// arithmetic before the budget comparison or signer call. A wrapping sum must
// never turn an enormous requested outflow into a small allowed value.
func TestAllowanceRejectsRecipientPlusFeeOverflow(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()
	var signerCalls atomic.Int32

	_, _, err := led.Issue(
		ctx, "vault-a", digest(0xba), math.MaxInt64, 1, math.MaxInt64,
		func(context.Context) (string, error) {
			signerCalls.Add(1)
			return "must-not-sign", nil
		},
	)
	if err == nil {
		t.Fatal("recipient+fee int64 overflow was accepted")
	}
	if signerCalls.Load() != 0 {
		t.Fatal("overflowing outflow reached signer")
	}
	spent, spentErr := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
	if spentErr != nil {
		t.Fatal(spentErr)
	}
	if spent != 0 {
		t.Fatalf("overflowing request consumed %d sats, want 0", spent)
	}
}
