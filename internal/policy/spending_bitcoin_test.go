package policy

import (
	"encoding/json"
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

func TestSpendingBitcoinRejectsHistoricalRenewal(t *testing.T) {
	for _, kind := range []string{"", "vault-light-policy-v1", "savings-setup-v1"} {
		t.Run(kind, func(t *testing.T) {
			l, _, op := renewalFixture(t)
			op.Kind, op.AmountSats = kind, 0
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err == nil {
				t.Fatal("retired batch admitted")
			}
			var n int
			if err := l.db.QueryRow(`SELECT COUNT(*) FROM light_renewal_operation`).Scan(&n); err != nil || n != 0 {
				t.Fatal("retired batch persisted", n, err)
			}
		})
	}
}

func TestRetiredRenewalRowsCannotBecomeBitcoinPayments(t *testing.T) {
	l, now, op := renewalFixture(t)
	op.Kind, op.AmountSats, op.CreatedAt = "", 0, now.Format(time.RFC3339)
	raw, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`INSERT INTO light_renewal_operation VALUES(?,?,?,?)`, op.OperationID, op.VaultID, string(raw), renewalMAC(testIntegrityKey(), "vaulted-light/renewal-operation/v1", string(raw))); err != nil {
		t.Fatal(err)
	}
	if _, err := l.GetLightRenewal(t.Context(), op.OperationID); err == nil {
		t.Fatal("retired renewal became a current payment")
	}
	if _, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err == nil {
		t.Fatal("unsupported authority ignored by allowance")
	}
}
