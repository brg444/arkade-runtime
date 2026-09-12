package policy

import "testing"

func TestRetiredSavingsSetupCannotReserveAllowance(t *testing.T) {
	l, _, op := renewalFixture(t)
	op.Kind, op.AmountSats = "savings-setup-v1", 1000
	if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err == nil {
		t.Fatal("retired operation admitted")
	}
	var rows int
	if err := l.db.QueryRow(`SELECT count(*) FROM light_renewal_operation`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("retired admission wrote %d rows: %v", rows, err)
	}
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("retired admission charged %d: %v", used, err)
	}
}
