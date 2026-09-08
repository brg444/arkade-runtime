package policy

import (
	"bytes"
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
func TestSpendingBitcoinMigrationPreservesPendingSetupBytes(t *testing.T) {
	l, _, op := renewalFixture(t)
	op.Kind = SavingsSetupBatchKind
	op.AmountSats = 1000
	if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized", "final_dispatched"} {
		appendRenewal(t, l, op, phase)
	}
	var before string
	var macBefore []byte
	if err := l.db.QueryRow(`SELECT payload,integrity_mac FROM light_renewal_operation`).Scan(&before, &macBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`UPDATE schema_meta SET version=6`); err != nil {
		t.Fatal(err)
	}
	if err := applySpendingBitcoinMigration(l.db); err != nil {
		t.Fatal(err)
	}
	var after string
	var macAfter []byte
	if err := l.db.QueryRow(`SELECT payload,integrity_mac FROM light_renewal_operation`).Scan(&after, &macAfter); err != nil {
		t.Fatal(err)
	}
	if before != after || !bytes.Equal(macBefore, macAfter) {
		t.Fatal("signed setup record changed")
	}
	saved, err := l.GetLightRenewal(t.Context(), op.OperationID)
	if err != nil || saved.Events["final_dispatched"].Phase == "" {
		t.Fatal("lost final dispatch", err)
	}
	if version, err := l.SchemaVersion(); err != nil || version != 7 {
		t.Fatalf("reader fence %d %v", version, err)
	}
}

func TestSpendingBitcoinAndLegacyFundingShareReservationFence(t *testing.T) {
	for _, kind := range []string{SavingsSetupBatchKind, SpendingBitcoinBatchKind} {
		t.Run(kind, func(t *testing.T) {
			l, _, op := renewalFixture(t)
			op.Kind = kind
			op.AmountSats = 1000
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized", "final_dispatched"} {
				appendRenewal(t, l, op, phase)
			}
			op.OperationID = "abababababababababababababababab"
			if kind == SavingsSetupBatchKind {
				op.Kind = SpendingBitcoinBatchKind
				op.AmountSats = 1500
			} else {
				op.Kind = SavingsSetupBatchKind
			}
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); !errors.Is(err, ErrVtxoOperationActive) {
				t.Fatalf("second payment allowed across route kinds: %v", err)
			}
		})
	}
}
