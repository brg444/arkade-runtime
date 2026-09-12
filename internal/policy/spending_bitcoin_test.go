package policy

import (
	"errors"
	"testing"
	"time"
)

func TestSpendingBitcoinChargesPrincipalAndRetainsFinalDispatch(t *testing.T) {
	l, now, op := renewalFixture(t)
	op.Kind = SpendingBitcoinBatchKind
	op.AmountSats = 1500
	if _, err := l.ReserveLightRenewal(t.Context(), op, 1500); !errors.Is(err, ErrPeriodAllowanceExceeded) {
		t.Fatal(err)
	}
	if _, err := l.ReserveLightRenewal(t.Context(), op, 1623); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized", "final_dispatched"} {
		appendRenewal(t, l, op, phase)
	}
	*now = now.Add(48 * time.Hour)
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 1623 {
		t.Fatalf("%d %v", used, err)
	}
	if _, _, err := l.AppendLightRenewalEvent(t.Context(), LightRenewalEvent{OperationID: op.OperationID, Phase: "released", RequestDigest: op.PlanDigest, Evidence: `{"unspent":true}`}, nil, 0); err == nil {
		t.Fatal("released escaped signature")
	}
}

func TestSpendingBitcoinSharesRenewalReservationFence(t *testing.T) {
	for _, kind := range []string{"", SpendingBitcoinBatchKind} {
		t.Run(kind, func(t *testing.T) {
			l, _, op := renewalFixture(t)
			op.Kind = kind
			op.AmountSats = 1000
			if kind == "" {
				op.AmountSats = 0
			}
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized", "final_dispatched"} {
				appendRenewal(t, l, op, phase)
			}
			op.OperationID = "abababababababababababababababab"
			if kind == "" {
				op.Kind = SpendingBitcoinBatchKind
				op.AmountSats = 1500
			} else {
				op.Kind = ""
				op.AmountSats = 0
			}
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); !errors.Is(err, ErrVtxoOperationActive) {
				t.Fatalf("second payment allowed across route kinds: %v", err)
			}
		})
	}
}
