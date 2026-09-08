package policy

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

func rollingFixture(t *testing.T) (*Ledger, *time.Time, *rolling.Contract, RollingOperation) {
	return rollingFixtureWithGrant(t, false)
}

func rollingFixtureWithGrant(t *testing.T, automatic bool) (*Ledger, *time.Time, *rolling.Contract, RollingOperation) {
	t.Helper()
	l, now, legacy := renewalFixture(t)
	c, proposal, err := fixture.RollingPayment()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := rolling.EncodeDescriptor(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.EnrollRolling(t.Context(), RollingEnrollment{VaultID: legacy.VaultID, ControllerID: c.Parameters.ControllerID.String(), Descriptor: string(descriptor), BootstrapTxid: proposal.Sources[0].Previous.TxHash().String(), AutomaticRenewal: automatic}); err != nil {
		t.Fatal(err)
	}
	op := RollingOperation{OperationID: proposal.Transaction.TxHash().String(), VaultID: legacy.VaultID, Proposal: proposal}
	return l, now, c, op
}
func rollingEvent(t *testing.T, l *Ledger, op RollingOperation, phase string) RollingEvent {
	t.Helper()
	e := RollingEvent{OperationID: op.OperationID, Phase: phase}
	if phase == "authorized" {
		e.Evidence = `{"fixture":"retained signatures"}`
	}
	if phase == "finalized" {
		e.Evidence = `{"fixture":"resolved admission"}`
		e.OutcomeTxid = op.OperationID
	}
	var result RollingEvent
	var err error
	if phase == "authorized" {
		result, err = l.CommitRollingAuthorization(t.Context(), e, []byte{0x51, 0x52}, 1)
	} else {
		result, err = l.AppendRollingEvent(t.Context(), e)
	}
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestRollingJournalHoldsUncertainAndPreservesFirstObservation(t *testing.T) {
	l, now, _, op := rollingFixture(t)
	if _, err := l.ReserveRolling(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	rollingEvent(t, l, op, "authorized")
	rollingEvent(t, l, op, "submitted")
	*now = now.Add(48 * time.Hour)
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 1000 {
		t.Fatalf("uncertain debit: %d %v", used, err)
	}
	if _, err := l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "aborted"}); err == nil {
		t.Fatal("signed operation released")
	}
	finalized := rollingEvent(t, l, op, "finalized")
	*now = now.Add(24 * time.Hour)
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 1000 {
		t.Fatalf("closed boundary: %d %v", used, err)
	}
	*now = now.Add(500 * time.Millisecond)
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 1000 {
		t.Fatalf("fractional maturity boundary: %d %v", used, err)
	}
	*now = now.Add(500 * time.Millisecond)
	repeated, err := l.AppendRollingEvent(t.Context(), finalized)
	if err != nil || repeated.CreatedAt != finalized.CreatedAt {
		t.Fatalf("first observation changed: %v", err)
	}
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("mature debit: %d %v", used, err)
	}
	if _, err := l.ReserveRolling(t.Context(), op, 10000); err != nil {
		t.Fatalf("exact restart retry: %v", err)
	}
}
func TestRollingJournalConcurrentReservationAndSharedAllowance(t *testing.T) {
	l, _, _, op := rollingFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := l.ReserveRolling(context.Background(), op, 1000); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	all, err := l.RollingOperations(t.Context(), op.VaultID)
	if err != nil || len(all) != 1 {
		t.Fatalf("duplicate reservation: %d %v", len(all), err)
	}
	// A reservation from the pre-existing renewal path observes the new debit.
	legacy := LightRenewalOperation{OperationID: strings.Repeat("23", 16), VaultID: op.VaultID, InputTxid: strings.Repeat("24", 32), FeeSats: 1, PlanDigest: strings.Repeat("25", 32), Plan: `{"fixture":true}`, ExpiresAt: l.NowUTC().Add(time.Minute).Format(time.RFC3339)}
	if _, err := l.ReserveLightRenewal(t.Context(), legacy, 1000); !errors.Is(err, ErrPeriodAllowanceExceeded) {
		t.Fatalf("shared allowance bypass: %v", err)
	}
}
func TestRollingJournalRejectsTamperingBeforeFiltering(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"hidden operation", `UPDATE rolling_operation SET vault_id=?`},
		{"hidden event", `UPDATE rolling_event SET phase='aborted'`},
		{"payload", `UPDATE rolling_operation SET payload='{}'`},
		{"enrollment", `UPDATE rolling_enrollment SET controller_id='changed'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _, _, op := rollingFixture(t)
			if _, err := l.ReserveRolling(t.Context(), op, 10000); err != nil {
				t.Fatal(err)
			}
			rollingEvent(t, l, op, "authorized")
			var err error
			if tc.name == "hidden operation" {
				vault := strings.Repeat("bb", 32)
				createPolicyTestVault(t, l, vault, 0x61)
				existing, _ := l.RollingOperations(t.Context(), op.VaultID)
				enrollment := existing[0].Enrollment
				enrollment.VaultID = vault
				contract, decodeErr := rolling.DecodeDescriptor([]byte(enrollment.Descriptor))
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				contract.Parameters.ControllerID.Txid[0]++
				descriptor, encodeErr := rolling.EncodeDescriptor(contract)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				enrollment.Descriptor = string(descriptor)
				enrollment.ControllerID = contract.Parameters.ControllerID.String()
				_, err = l.EnrollRolling(t.Context(), enrollment)
				if err == nil {
					_, err = l.db.Exec(tc.sql, vault)
				}
			} else {
				_, err = l.db.Exec(tc.sql)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.SpentInPeriod(t.Context(), op.VaultID, ""); err == nil {
				t.Fatal("tampered row was hidden")
			}
		})
	}
}

func TestRollingJournalRestartRestoresControllerAndHistory(t *testing.T) {
	l, now, c, op := rollingFixture(t)
	if _, err := l.ReserveRolling(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	rollingEvent(t, l, op, "authorized")
	rollingEvent(t, l, op, "submitted")
	final := rollingEvent(t, l, op, "finalized")
	before, err := l.RollingHistory(t.Context(), op.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	var sequence int
	var name, path string
	if err = l.db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenLedger(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err = restarted.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	after, err := restarted.RollingHistory(t.Context(), op.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(before)
	right, _ := json.Marshal(after)
	if string(left) != string(right) {
		t.Fatal("restart changed controller or debit history")
	}
	if after.State.Remaining != c.Parameters.Budget-1000 || after.ControllerTxid != op.OperationID || len(after.Debits) != 1 {
		t.Fatal("lost finalized controller state")
	}
	*now = now.Add(time.Hour)
	replayed, err := restarted.AppendRollingEvent(t.Context(), final)
	if err != nil || replayed.CreatedAt != final.CreatedAt {
		t.Fatal("restart changed first observation", err)
	}
}

func TestRollingMutationDetectsRollbackBeforeAppending(t *testing.T) {
	l, _, _, op := rollingFixture(t)
	// The fixture enrolled before attaching the external sequence; establish
	// that pre-existing record only inside this test, then attach normally.
	sequence, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err = sequence.Observe(0); err != nil {
		t.Fatal(err)
	}
	if err = l.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, err = l.ReserveRolling(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.Exec(`DELETE FROM rolling_operation WHERE operation_id=?`, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.ReserveRolling(t.Context(), op, 10000); err == nil {
		t.Fatal("append concealed a database rollback")
	}
	var count int
	if err = l.db.QueryRow(`SELECT COUNT(*) FROM rolling_operation`).Scan(&count); err != nil || count != 0 {
		t.Fatal("rollback refusal mutated journal", err)
	}
}

func TestRollingAuthorizationAtomicallyCommitsCredential(t *testing.T) {
	l, _, _, op := rollingFixture(t)
	if _, err := l.ReserveRolling(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	e := RollingEvent{OperationID: op.OperationID, Phase: "authorized", Evidence: `{"signed":"exact bytes"}`}
	if _, err := l.AppendRollingEvent(t.Context(), e); err == nil {
		t.Fatal("uncredentialed authorization accepted")
	}
	if _, err := l.CommitRollingAuthorization(t.Context(), e, []byte{0x61}, 1); err == nil {
		t.Fatal("wrong credential accepted")
	}
	records, err := l.RollingOperations(t.Context(), op.VaultID)
	if err != nil || len(records[0].Events) != 0 {
		t.Fatal("failed credential left authorization", err)
	}
	first, err := l.CommitRollingAuthorization(t.Context(), e, []byte{0x51, 0x52}, 1)
	if err != nil {
		t.Fatal(err)
	}
	again, err := l.CommitRollingAuthorization(t.Context(), e, []byte{0x51, 0x52}, 1)
	if err != nil || first != again {
		t.Fatal("exact counter retry failed", err)
	}
	if _, err = l.CommitRollingAuthorization(t.Context(), e, []byte{0x51, 0x52}, 2); err == nil {
		t.Fatal("retry advanced counter")
	}
	changed := e
	changed.Evidence = `{"signed":"different bytes"}`
	if _, err = l.CommitRollingAuthorization(t.Context(), changed, []byte{0x51, 0x52}, 1); err == nil {
		t.Fatal("retry changed signatures")
	}
}
