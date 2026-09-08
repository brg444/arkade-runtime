package policy

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

func rollingRenewalFixture(t *testing.T) (*Ledger, *time.Time, RollingOperation) {
	t.Helper()
	l, now, c, op := rollingFixture(t)
	built, err := rolling.BuildRenewal(c, op.Proposal.Sources, op.Proposal.Proof, 100, now.Unix(), now.Unix()+600)
	if err != nil {
		t.Fatal(err)
	}
	op.Proposal = rolling.Proposal{Kind: rolling.RenewalOperation, Message: built.Message, Transaction: built.Proof.UnsignedTx, Sources: op.Proposal.Sources, Proof: op.Proposal.Proof, CheckpointExit: c.Parameters.CheckpointExit}
	op.OperationID = op.Proposal.Transaction.TxHash().String()
	if _, err = l.ReserveRolling(t.Context(), op, c.Parameters.Budget); err != nil {
		t.Fatal(err)
	}
	rollingEvent(t, l, op, "authorized")
	return l, now, op
}

func appendRollingRenewalStage(t *testing.T, l *Ledger, id, phase string) {
	t.Helper()
	if _, err := l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: id, Phase: phase, Evidence: `{}`}); err != nil {
		t.Fatal(err)
	}
}

func TestRollingRenewalFinalAuthorityAndCleanupAreAtomic(t *testing.T) {
	l, _, op := rollingRenewalFixture(t)
	for _, phase := range []string{"emulator_authorized", "register_dispatched", "registered", "tree_requested", "tree_prepared", "nonces_committed", "tree_signed"} {
		appendRollingRenewalStage(t, l, op.OperationID, phase)
	}
	var wait sync.WaitGroup
	errors := make(chan error, 2)
	start := make(chan struct{})
	for _, cleanup := range []bool{true, false} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			var err error
			if cleanup {
				_, err = l.BeginRollingCleanup(t.Context(), op.OperationID)
			} else {
				_, err = l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "final_authorized", Evidence: `{}`})
			}
			errors <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("authority races admitted %d winners", successes)
	}
	records, err := l.RollingOperations(t.Context(), op.VaultID)
	if err != nil || len(records) != 1 {
		t.Fatal(err)
	}
	_, cleanup := records[0].Events["cleanup_pending"]
	_, final := records[0].Events["final_authorized"]
	if cleanup == final {
		t.Fatal("conflicting authority persisted")
	}
}

func TestRollingCleanupRetainsDeadlineAndUncertainController(t *testing.T) {
	l, now, op := rollingRenewalFixture(t)
	if _, err := l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "submitted"}); err == nil {
		t.Fatal("renewal submitted without final authority")
	}
	first, err := l.BeginRollingCleanup(t.Context(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	var deadline RollingCleanupDeadline
	if err = json.Unmarshal([]byte(first.Evidence), &deadline); err != nil || deadline.ExpiresAt != now.Unix()+rolling.CleanupLifetimeSeconds-1 {
		t.Fatal("untrusted cleanup clock", err)
	}
	for _, phase := range []string{"cleanup_authorized", "cleanup_dispatched", "cleanup_result"} {
		appendRollingRenewalStage(t, l, op.OperationID, phase)
	}
	*now = now.Add(48 * time.Hour)
	retried, err := l.BeginRollingCleanup(t.Context(), op.OperationID)
	if err != nil || retried != first {
		t.Fatal("cleanup retry renewed its authority", err)
	}
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 100 {
		t.Fatal("cleanup expiry released uncertain fee", used, err)
	}
	history, err := l.RollingHistory(t.Context(), op.VaultID)
	if err != nil || history.Pending == nil || history.Pending.OperationID != op.OperationID {
		t.Fatal("cleanup released controller", err)
	}
	for _, phase := range []string{"register_dispatched", "final_authorized", "submitted", "aborted"} {
		if _, err = l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: phase, Evidence: `{}`}); err == nil {
			t.Fatalf("cleanup admitted %s", phase)
		}
	}
}

func TestRollingRenewalRejectsSkippedStagesAndNativeCleanup(t *testing.T) {
	l, _, op := rollingRenewalFixture(t)
	for _, phase := range []string{"registered", "nonces_committed", "tree_signed", "final_authorized", "cleanup_authorized", "cleanup_result"} {
		if _, err := l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: phase, Evidence: `{}`}); err == nil {
			t.Fatalf("skipped predecessor for %s", phase)
		}
	}
	native, _, c, payment := rollingFixture(t)
	if _, err := native.ReserveRolling(t.Context(), payment, c.Parameters.Budget); err != nil {
		t.Fatal(err)
	}
	rollingEvent(t, native, payment, "authorized")
	if _, err := native.BeginRollingCleanup(t.Context(), payment.OperationID); err == nil {
		t.Fatal("native operation acquired a cleanup capability")
	}
}

func TestRollingRenewalRestartPreservesExclusiveAuthority(t *testing.T) {
	for _, cleanup := range []bool{true, false} {
		name := "final"
		if cleanup {
			name = "cleanup"
		}
		t.Run(name, func(t *testing.T) {
			l, now, op := rollingRenewalFixture(t)
			var deadline RollingEvent
			var err error
			if cleanup {
				deadline, err = l.BeginRollingCleanup(t.Context(), op.OperationID)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				for _, phase := range []string{"emulator_authorized", "register_dispatched", "registered", "tree_requested", "tree_prepared", "nonces_committed", "tree_signed", "final_authorized"} {
					appendRollingRenewalStage(t, l, op.OperationID, phase)
				}
				if _, err = l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "submitted"}); err == nil {
					t.Fatal("submission without durable final signatures")
				}
				appendRollingRenewalStage(t, l, op.OperationID, "final_signed")
			}
			var sequence int
			var dbName, path string
			if err = l.db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &dbName, &path); err != nil {
				t.Fatal(err)
			}
			if err = l.Close(); err != nil {
				t.Fatal(err)
			}
			*now = now.Add(48 * time.Hour)
			restarted, err := OpenLedger(path, func() time.Time { return *now })
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if err = restarted.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if used, err := restarted.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 100 {
				t.Fatal("restart released uncertain renewal fee", used, err)
			}
			if cleanup {
				retry, err := restarted.BeginRollingCleanup(t.Context(), op.OperationID)
				if err != nil || retry != deadline {
					t.Fatal("restart changed cleanup deadline", err)
				}
				if _, err = restarted.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "final_authorized", Evidence: `{}`}); err == nil {
					t.Fatal("restart lost cleanup fence")
				}
			} else {
				if _, err = restarted.BeginRollingCleanup(t.Context(), op.OperationID); err == nil {
					t.Fatal("restart lost final authority")
				}
				appendRollingRenewalStage(t, restarted, op.OperationID, "final_signed")
				if _, err = restarted.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "submitted"}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRollingRenewalExpiryPreventsNewFinalAuthority(t *testing.T) {
	for _, retainFinal := range []bool{false, true} {
		l, now, op := rollingRenewalFixture(t)
		for _, phase := range []string{"emulator_authorized", "register_dispatched", "registered", "tree_requested", "tree_prepared", "nonces_committed", "tree_signed"} {
			appendRollingRenewalStage(t, l, op.OperationID, phase)
		}
		phase := "final_authorized"
		if retainFinal {
			appendRollingRenewalStage(t, l, op.OperationID, phase)
			phase = "final_signed"
		}
		*now = now.Add(10 * time.Minute)
		if _, err := l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: phase, Evidence: `{}`}); err == nil {
			t.Fatal("expired renewal acquired new final authority", phase)
		}
		if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 100 {
			t.Fatal("expired final authority released uncertain fee", used, err)
		}
	}
}
