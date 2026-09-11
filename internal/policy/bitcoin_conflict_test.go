package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func dispatchedBitcoinConflictFixture(t *testing.T, kind string) (*Ledger, LightRenewalOperation, LightRenewalEvent) {
	t.Helper()
	l, _, op := renewalFixture(t)
	op.Kind = kind
	if kind != "" {
		op.AmountSats = 1000
	}
	if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"register_authorized", "register_dispatched", "register_result", "final_authorized", "final_dispatched"} {
		appendRenewal(t, l, op, phase)
	}
	p := BitcoinConflictEvidence{Kind: BitcoinConflictKind, CommitmentTxid: strings.Repeat("11", 32), FundingTxid: strings.Repeat("22", 32), ConflictingTxid: strings.Repeat("33", 32), BlockHash: strings.Repeat("44", 32), BlockHeight: 100, TipHash: strings.Repeat("55", 32), TipHeight: 105, RawTransaction: "00"}
	raw, _ := json.Marshal(p)
	return l, op, LightRenewalEvent{OperationID: op.OperationID, Phase: "released", RequestDigest: op.PlanDigest, Evidence: string(raw)}
}
func TestBitcoinConflictReleaseFencesAndRetainsEvidence(t *testing.T) {
	for _, kind := range []string{SavingsSetupBatchKind, SpendingBitcoinBatchKind} {
		t.Run(kind, func(t *testing.T) {
			l, op, event := dispatchedBitcoinConflictFixture(t, kind)
			before, err := l.GetLightRenewal(t.Context(), op.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			// The reader fence changes only the version, never authenticated records.
			var payload string
			var mac []byte
			if err := l.db.QueryRow(`SELECT payload,integrity_mac FROM light_renewal_operation`).Scan(&payload, &mac); err != nil {
				t.Fatal(err)
			}
			if _, err := l.db.Exec(`UPDATE schema_meta SET version=7`); err != nil {
				t.Fatal(err)
			}
			if err := applyBitcoinConflictMigration(l.db); err != nil {
				t.Fatal(err)
			}
			var afterPayload string
			var afterMAC []byte
			if err := l.db.QueryRow(`SELECT payload,integrity_mac FROM light_renewal_operation`).Scan(&afterPayload, &afterMAC); err != nil {
				t.Fatal(err)
			}
			if payload != afterPayload || !bytes.Equal(mac, afterMAC) {
				t.Fatal("migration rewrote authenticated operation")
			}
			if version, err := l.SchemaVersion(); err != nil || version != 8 {
				t.Fatalf("schema %d: %v", version, err)
			}
			if _, created, err := l.AppendLightRenewalEvent(t.Context(), event, nil, 0); err != nil || !created {
				t.Fatalf("release %v %v", created, err)
			}
			if _, created, err := l.AppendLightRenewalEvent(t.Context(), event, nil, 0); err != nil || created {
				t.Fatalf("replay %v %v", created, err)
			}
			saved, err := l.GetLightRenewal(t.Context(), op.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			for phase, e := range before.Events {
				if saved.Events[phase] != e {
					t.Fatal("lost signed evidence", phase)
				}
			}
			if saved.Events["released"].Evidence != event.Evidence {
				t.Fatal("lost conflict proof")
			}
			if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 0 {
				t.Fatalf("allowance %d %v", used, err)
			}
			for _, phase := range []string{"confirmed", "final_result"} {
				late := LightRenewalEvent{OperationID: op.OperationID, Phase: phase, RequestDigest: op.PlanDigest, Outcome: "submitted"}
				if phase == "confirmed" {
					late.Outcome = "confirmed"
					late.OperatorRef = strings.Repeat("77", 32)
					late.Evidence = `{"confirmed":true}`
				}
				if _, _, err := l.AppendLightRenewalEvent(t.Context(), late, nil, 0); err == nil {
					t.Fatal("late result accepted", phase)
				}
			}
			op.OperationID = strings.Repeat("99", 16)
			if _, err := l.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
				t.Fatal("released input remains reserved", err)
			}
		})
	}
}
func TestBitcoinConflictReleaseRejectsUnboundEvidence(t *testing.T) {
	for _, scenario := range []string{"ordinary renewal", "wrong digest", "shallow", "unknown field", "unspent only"} {
		t.Run(scenario, func(t *testing.T) {
			kind := SpendingBitcoinBatchKind
			if scenario == "ordinary renewal" {
				kind = ""
			}
			l, op, event := dispatchedBitcoinConflictFixture(t, kind)
			switch scenario {
			case "wrong digest":
				event.RequestDigest = strings.Repeat("ff", 32)
			case "shallow":
				event.Evidence = strings.Replace(event.Evidence, `"tipHeight":105`, `"tipHeight":104`, 1)
			case "unknown field":
				event.Evidence = strings.TrimSuffix(event.Evidence, "}") + `,"extra":true}`
			case "unspent only":
				event.Evidence = `{"unspent":true}`
			}
			if _, _, err := l.AppendLightRenewalEvent(t.Context(), event, nil, 0); err == nil {
				t.Fatal("invalid release accepted")
			}
			if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 123+op.AmountSats {
				t.Fatalf("reservation changed %d %v", used, err)
			}
		})
	}
}
func TestBitcoinConflictReleaseRacesConfirmation(t *testing.T) {
	l, op, event := dispatchedBitcoinConflictFixture(t, SpendingBitcoinBatchKind)
	appendRenewal(t, l, op, "final_result")
	confirmed := LightRenewalEvent{OperationID: op.OperationID, Phase: "confirmed", RequestDigest: op.PlanDigest, Outcome: "confirmed", OperatorRef: strings.Repeat("77", 32), Evidence: `{"confirmed":true}`}
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, e := range []LightRenewalEvent{event, confirmed} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := l.AppendLightRenewalEvent(t.Context(), e, nil, 0)
			outcomes <- err
		}()
	}
	wg.Wait()
	close(outcomes)
	successes := 0
	for err := range outcomes {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("terminal transitions succeeded %d times", successes)
	}
}

func TestEndedOperatorBatchReleaseBindsDispatchAndLiveInput(t *testing.T) {
	for _, kind := range []string{SavingsSetupBatchKind, SpendingBitcoinBatchKind} {
		t.Run(kind, func(t *testing.T) {
			l, op, event := dispatchedBitcoinConflictFixture(t, kind)
			snapshot, err := l.GetLightRenewal(t.Context(), op.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			dispatchedAt, err := time.Parse(time.RFC3339, snapshot.Events["final_dispatched"].CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			expiresAt, err := time.Parse(time.RFC3339, op.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			proof := BitcoinEndedBatchEvidence{
				Kind:                 BitcoinEndedBatchKind,
				CommitmentTxid:       strings.Repeat("11", 32),
				BatchEndedAt:         dispatchedAt.Unix() - 1,
				FinalDispatchedAt:    snapshot.Events["final_dispatched"].CreatedAt,
				InputTxid:            op.InputTxid,
				InputVout:            op.InputVout,
				InputValueSats:       uint64(op.AmountSats + op.FeeSats),
				InputExpiresAt:       expiresAt.Unix(),
				InputCommitmentTxids: []string{strings.Repeat("22", 32)},
			}
			raw, _ := json.Marshal(proof)
			event.Evidence = string(raw)
			if _, created, err := l.AppendLightRenewalEvent(t.Context(), event, nil, 0); err != nil || !created {
				t.Fatalf("ended batch release %v %v", created, err)
			}
			if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 0 {
				t.Fatalf("allowance %d %v", used, err)
			}
		})
	}
}

func TestEndedOperatorBatchReleaseRejectsAmbiguousOrdering(t *testing.T) {
	l, op, event := dispatchedBitcoinConflictFixture(t, SpendingBitcoinBatchKind)
	snapshot, err := l.GetLightRenewal(t.Context(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	dispatchedAt, _ := time.Parse(time.RFC3339, snapshot.Events["final_dispatched"].CreatedAt)
	expiresAt, _ := time.Parse(time.RFC3339, op.ExpiresAt)
	proof := BitcoinEndedBatchEvidence{
		Kind:                 BitcoinEndedBatchKind,
		CommitmentTxid:       strings.Repeat("11", 32),
		BatchEndedAt:         dispatchedAt.Unix(),
		FinalDispatchedAt:    snapshot.Events["final_dispatched"].CreatedAt,
		InputTxid:            op.InputTxid,
		InputVout:            op.InputVout,
		InputValueSats:       uint64(op.AmountSats + op.FeeSats),
		InputExpiresAt:       expiresAt.Unix(),
		InputCommitmentTxids: []string{strings.Repeat("22", 32)},
	}
	raw, _ := json.Marshal(proof)
	event.Evidence = string(raw)
	if _, _, err := l.AppendLightRenewalEvent(t.Context(), event, nil, 0); err == nil {
		t.Fatal("equal second-resolution timestamps proved dispatch ordering")
	}
	if used, err := l.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used == 0 {
		t.Fatalf("ambiguous dispatch released allowance %d %v", used, err)
	}
}
