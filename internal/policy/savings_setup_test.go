package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSavingsSetupChargesPrincipalAndRetainsUncertainOutflow(t *testing.T) {
	l, now, op := renewalFixture(t)
	op.Kind, op.AmountSats = SavingsSetupBatchKind, 1000
	if _, err := l.ReserveLightRenewal(context.Background(), op, 1000); !errors.Is(err, ErrPeriodAllowanceExceeded) {
		t.Fatalf("principal plus fee not checked: %v", err)
	}
	if _, err := l.ReserveLightRenewal(context.Background(), op, 1123); err != nil {
		t.Fatal(err)
	}
	appendRenewal(t, l, op, "register_authorized")
	appendRenewal(t, l, op, "register_dispatched")
	*now = now.Add(48 * time.Hour)
	used, err := l.SpentInPeriod(context.Background(), op.VaultID, "")
	if err != nil || used != 1123 {
		t.Fatalf("uncertain setup outflow: %d %v", used, err)
	}
	op.OperationID = strings.Repeat("91", 16)
	op.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	if _, err := l.ReserveLightRenewal(context.Background(), op, 100000); !errors.Is(err, ErrVtxoOperationActive) {
		t.Fatalf("allowed another setup: %v", err)
	}
}

func TestSavingsSetupKindAndAmountAreAuthenticated(t *testing.T) {
	l, _, op := renewalFixture(t)
	op.Kind, op.AmountSats = SavingsSetupBatchKind, 500
	if _, err := l.ReserveLightRenewal(context.Background(), op, 10000); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`UPDATE light_renewal_operation SET payload=replace(payload,'"amountSats":500','"amountSats":0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.SpentInPeriod(context.Background(), op.VaultID, ""); err == nil {
		t.Fatal("tampered setup amount accepted")
	}
}

func TestSavingsSetupReaderMigrationPreservesLegacyBatchBytes(t *testing.T) {
	l, _, op := renewalFixture(t)
	if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	var before string
	var macBefore []byte
	if err := l.db.QueryRow(`SELECT payload,integrity_mac FROM light_renewal_operation`).Scan(&before, &macBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`UPDATE schema_meta SET version=5`); err != nil {
		t.Fatal(err)
	}
	if err := applySavingsSetupMigration(l.db); err != nil {
		t.Fatal(err)
	}
	var after string
	var macAfter []byte
	if err := l.db.QueryRow(`SELECT payload,integrity_mac FROM light_renewal_operation`).Scan(&after, &macAfter); err != nil {
		t.Fatal(err)
	}
	if before != after || !bytes.Equal(macBefore, macAfter) {
		t.Fatal("legacy batch authentication changed")
	}
	if strings.Contains(after, "amountSats") || strings.Contains(after, `"kind"`) {
		t.Fatal("legacy MAC preimage gained new fields")
	}
	if version, err := l.SchemaVersion(); err != nil || version != 6 {
		t.Fatalf("reader fence %d %v", version, err)
	}
}

func TestSavingsSetupCannotReleaseWithoutDeleteOrFinalizeAfterDelete(t *testing.T) {
	for _, finalAuthorized := range []bool{false, true} {
		t.Run(fmt.Sprint(finalAuthorized), func(t *testing.T) {
			l, now, op := renewalFixture(t)
			op.Kind, op.AmountSats = SavingsSetupBatchKind, 1000
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"register_authorized", "register_dispatched", "register_result"} {
				appendRenewal(t, l, op, phase)
			}
			if finalAuthorized {
				appendRenewal(t, l, op, "final_authorized")
			}
			*now = now.Add(6 * time.Minute)
			released := LightRenewalEvent{OperationID: op.OperationID, Phase: "released", RequestDigest: op.PlanDigest, Evidence: `{"input":"unspent"}`}
			if _, _, err := l.AppendLightRenewalEvent(t.Context(), released, nil, 0); err == nil {
				t.Fatal("expiry and unspent input released queued intent")
			}
			for _, phase := range []string{"delete_authorized", "delete_dispatched"} {
				appendRenewal(t, l, op, phase)
			}
			if _, _, err := l.AppendLightRenewalEvent(t.Context(), released, nil, 0); err == nil {
				t.Fatal("ambiguous delete released reservation")
			}
			for _, phase := range []string{"final_authorized", "final_dispatched"} {
				event := LightRenewalEvent{OperationID: op.OperationID, Phase: phase, RequestDigest: op.PlanDigest}
				if phase == "final_authorized" {
					event.Evidence = `{"changed":true}`
				}
				if _, _, err := l.AppendLightRenewalEvent(t.Context(), event, nil, 0); err == nil {
					t.Fatal("finalization raced deletion")
				}
			}
			appendRenewal(t, l, op, "delete_result")
			if _, _, err := l.AppendLightRenewalEvent(t.Context(), released, nil, 0); err != nil {
				t.Fatal(err)
			}
		})
	}
}
