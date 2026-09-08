package policy

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

func rollingGrantFixture(t *testing.T) (*Ledger, *time.Time, RollingOperation) {
	t.Helper()
	l, now, c, op := rollingFixtureWithGrant(t, true)
	built, err := rolling.BuildRenewal(c, op.Proposal.Sources, op.Proposal.Proof, 100, now.Unix(), now.Unix()+600)
	if err != nil {
		t.Fatal(err)
	}
	op.Proposal = rolling.Proposal{Kind: rolling.RenewalOperation, Message: built.Message, Transaction: built.Proof.UnsignedTx, Sources: op.Proposal.Sources, Proof: op.Proposal.Proof, CheckpointExit: c.Parameters.CheckpointExit}
	op.OperationID = op.Proposal.Transaction.TxHash().String()
	if _, err = l.ReserveRolling(t.Context(), op, c.Parameters.Budget); err != nil {
		t.Fatal(err)
	}
	return l, now, op
}

func TestRollingGrantLeavesPasskeyCounterUnchanged(t *testing.T) {
	l, now, op := rollingGrantFixture(t)
	cred := []byte{0x51, 0x52}
	if err := l.AdvanceSignCount(op.VaultID, cred, 5); err != nil {
		t.Fatal(err)
	}
	event := RollingEvent{OperationID: op.OperationID, Phase: "authorized", Evidence: `{"signed":"fixed renewal"}`}
	first, err := l.CommitRollingRenewalAuthorization(t.Context(), event)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(48 * time.Hour)
	for range 3 {
		retry, err := l.CommitRollingRenewalAuthorization(t.Context(), event)
		if err != nil || first != retry {
			t.Fatal("grant retry changed", err)
		}
	}
	if count, ok := setTestSignCount(t, l, op.VaultID, cred); !ok || count != 5 {
		t.Fatal("automatic renewal changed passkey counter", count)
	}
	if spent, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || spent != 100 {
		t.Fatal("automatic retries duplicated or released debit", spent, err)
	}
}

func TestRollingGrantAndForegroundCommitRace(t *testing.T) {
	l, _, op := rollingGrantFixture(t)
	cred := []byte{0x51, 0x52}
	if err := l.AdvanceSignCount(op.VaultID, cred, 5); err != nil {
		t.Fatal(err)
	}
	event := RollingEvent{OperationID: op.OperationID, Phase: "authorized", Evidence: `{"signed":"fixed renewal"}`}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, automatic := range []bool{false, true} {
		wg.Go(func() {
			<-start
			var err error
			if automatic {
				_, err = l.CommitRollingRenewalAuthorization(t.Context(), event)
			} else {
				_, err = l.CommitRollingAuthorization(t.Context(), event, cred, 6)
			}
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success < 1 {
		t.Fatal("neither authorization committed")
	}
	count, ok := setTestSignCount(t, l, op.VaultID, cred)
	if !ok || count < 5 || count > 6 || (success == 2 && count != 6) {
		t.Fatal("counter/race mismatch", count, success)
	}
	all, err := l.RollingOperations(t.Context(), op.VaultID)
	if err != nil || len(all) != 1 || len(all[0].Events) != 1 {
		t.Fatal("duplicate authorization", err)
	}
	if spent, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || spent != 100 {
		t.Fatal("duplicate allowance charge", spent, err)
	}
}

func TestRollingGrantTamperAndAbsentCompatibility(t *testing.T) {
	l, _, _, op := rollingFixture(t)
	var raw string
	if err := l.db.QueryRow(`SELECT payload FROM rolling_enrollment WHERE vault_id=?`, op.VaultID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["AutomaticRenewal"]; ok {
		t.Fatal("absent grant changed existing MAC preimage")
	}
	var enrollment RollingEnrollment
	if err := json.Unmarshal([]byte(raw), &enrollment); err != nil {
		t.Fatal(err)
	}
	enrollment.AutomaticRenewal = true
	if _, err := l.EnrollRolling(t.Context(), enrollment); err == nil {
		t.Fatal("retry upgraded absent grant")
	}
	modified, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.Exec(`UPDATE rolling_enrollment SET payload=? WHERE vault_id=?`, string(modified), op.VaultID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.RollingHistory(t.Context(), op.VaultID); err == nil {
		t.Fatal("grant tamper passed MAC")
	}
}

func TestRollingGrantAndTreeCommitsRejectExpiredClock(t *testing.T) {
	for _, phase := range []string{"authorized", "emulator_authorized", "register_dispatched", "tree_requested", "tree_prepared", "nonces_committed", "tree_signed"} {
		t.Run(phase, func(t *testing.T) {
			l, now, op := rollingGrantFixture(t)
			stages := []string{"authorized", "emulator_authorized", "register_dispatched", "registered", "tree_requested", "tree_prepared", "nonces_committed", "tree_signed"}
			for _, stage := range stages {
				if stage == phase {
					*now = now.Add(600 * time.Second)
				}
				event := RollingEvent{OperationID: op.OperationID, Phase: stage, Evidence: `{}`}
				var err error
				if stage == "authorized" {
					_, err = l.CommitRollingRenewalAuthorization(t.Context(), event)
				} else {
					_, err = l.AppendRollingEvent(t.Context(), event)
				}
				if stage == phase {
					if err == nil {
						t.Fatal("expired authority committed")
					}
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
