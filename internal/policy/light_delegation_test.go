package policy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func delegationFixture(t *testing.T) (*Ledger, *time.Time, LightDelegation) {
	t.Helper()
	l, now, r := renewalFixture(t)
	return l, now, LightDelegation{OperationID: r.OperationID, VaultID: r.VaultID, InputTxid: r.InputTxid, ValidAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), FeeSats: r.FeeSats, PlanDigest: r.PlanDigest, Plan: `{"owner":"signed"}`}
}
func stageDelegation(t *testing.T, l *Ledger, o LightDelegation, through string) *LightDelegationSnapshot {
	t.Helper()
	s, err := l.ScheduleLightDelegation(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if through == "armed" {
		return s
	}
	for _, phase := range delegationPhases {
		if strings.HasPrefix(phase, "cleanup_") {
			continue
		}
		s, err = l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, phase, `{}`, ""}, 100000)
		if err != nil {
			t.Fatal(phase, err)
		}
		if phase == through {
			return s
		}
	}
	t.Fatal("unknown phase", through)
	return nil
}
func TestLightDelegationPaymentInvalidationAndOverlap(t *testing.T) {
	for _, paymentFirst := range []bool{false, true} {
		t.Run(map[bool]string{true: "payment-first", false: "armed-first"}[paymentFirst], func(t *testing.T) {
			l, now, o := delegationFixture(t)
			payment := testVtxoOperation(o.VaultID, "payment", vtxoPurposeSpend, vtxoStateReserved, 1000, 0, *now)
			txid, _ := hex.DecodeString(o.InputTxid)
			input := VtxoOperationInput{Txid: txid, ValueSats: 2000, Script: []byte{0x51}}
			unrelated := o
			unrelated.OperationID = strings.Repeat("06", 16)
			unrelated.InputTxid = strings.Repeat("07", 32)
			if !paymentFirst {
				stageDelegation(t, l, o, "armed")
				stageDelegation(t, l, unrelated, "armed")
			}
			if err := l.ReserveVtxoOperation(t.Context(), payment, []VtxoOperationInput{input}, 100000); err != nil {
				t.Fatal(err)
			}
			if paymentFirst {
				if _, err := l.ScheduleLightDelegation(t.Context(), o); !errors.Is(err, ErrVtxoOperationActive) {
					t.Fatal("overlap", err)
				}
				if _, err := l.ScheduleLightDelegation(t.Context(), unrelated); err != nil {
					t.Fatal("unrelated schedule", err)
				}
			} else {
				all, err := l.ListLightDelegations(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range all {
					want := "armed"
					if s.Operation.OperationID == o.OperationID {
						want = "invalidated"
					}
					if s.State() != want {
						t.Fatal(s.State(), want)
					}
				}
			}
			if _, err := l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{unrelated.OperationID, "claimed", `{}`, ""}, 100000); !errors.Is(err, ErrVtxoOperationActive) {
				t.Fatal("claim while payment", err)
			}
		})
	}
}
func TestLightDelegationClaimAndPaymentAtomicWinner(t *testing.T) {
	for i := 0; i < 10; i++ {
		l, now, o := delegationFixture(t)
		stageDelegation(t, l, o, "armed")
		payment := testVtxoOperation(o.VaultID, "payment", vtxoPurposeSpend, vtxoStateReserved, 1000, 0, *now)
		// Disjoint inputs still share the active signing lifecycle.
		in := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x99}, 32), ValueSats: 2000, Script: []byte{0x51}}
		start := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := l.AdvanceLightDelegation(context.Background(), LightDelegationEvent{o.OperationID, "claimed", `{}`, ""}, 100000)
			results <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			results <- l.ReserveVtxoOperation(context.Background(), payment, []VtxoOperationInput{in}, 100000)
		}()
		close(start)
		wg.Wait()
		close(results)
		won, lost := 0, 0
		for err := range results {
			if err == nil {
				won++
			} else if errors.Is(err, ErrVtxoOperationActive) {
				lost++
			} else {
				t.Fatal(err)
			}
		}
		if won != 1 || lost != 1 {
			t.Fatal(won, lost)
		}
	}
}
func TestLightDelegationBoundedExpiryAndFinalFence(t *testing.T) {
	for _, phase := range []string{"armed", "claimed", "register_dispatched", "register_result", "tree_prepared", "nonces_committed", "tree_signed", "final_authorized", "final_dispatched", "final_result"} {
		t.Run(phase, func(t *testing.T) {
			l, now, o := delegationFixture(t)
			stageDelegation(t, l, o, phase)
			e := LightDelegationEvent{o.OperationID, "expired", `{"inputLive":true}`, ""}
			*now = time.Unix(o.ExpiresAt, 0)
			if _, err := l.AdvanceLightDelegation(t.Context(), e, 0); err == nil {
				t.Fatal("quarantine skipped")
			}
			*now = now.Add(31 * time.Second)
			if phase != "armed" && phase != "claimed" && !strings.HasPrefix(phase, "final_") {
				if _, err := l.AdvanceLightDelegation(t.Context(), e, 0); err == nil {
					t.Fatal("Operator cleanup bypassed")
				}
				for _, cleanup := range []string{"cleanup_pending", "cleanup_authorized", "cleanup_dispatched", "cleanup_result"} {
					if _, err := l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, cleanup, `{}`, ""}, 0); err != nil {
						t.Fatal(cleanup, err)
					}
				}
			}
			_, err := l.AdvanceLightDelegation(t.Context(), e, 0)
			final := strings.HasPrefix(phase, "final_")
			if final && err == nil {
				t.Fatal("released final authority")
			}
			if !final && err != nil {
				t.Fatal(err)
			}
			used, err := l.SpentInPeriod(t.Context(), o.VaultID, "")
			if err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if final {
				want = o.FeeSats
			}
			if used != want {
				t.Fatal("fee hold", used, want)
			}
			if !final {
				if _, err := l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, "final_authorized", `{}`, ""}, 0); err == nil {
					t.Fatal("final signed after terminal")
				}
			}
		})
	}
}
func TestLightDelegationFinalVersusExpiryRace(t *testing.T) {
	for _, late := range []bool{false, true} {
		l, now, o := delegationFixture(t)
		stageDelegation(t, l, o, "tree_signed")
		if late {
			*now = time.Unix(o.ExpiresAt+31, 0)
		}
		start := make(chan struct{})
		results := make(chan string, 2)
		var wg sync.WaitGroup
		for _, phase := range []string{"cleanup_pending", "final_authorized"} {
			wg.Add(1)
			go func(phase string) {
				defer wg.Done()
				<-start
				_, err := l.AdvanceLightDelegation(context.Background(), LightDelegationEvent{o.OperationID, phase, `{}`, ""}, 0)
				if err == nil {
					results <- phase
				}
			}(phase)
		}
		close(start)
		wg.Wait()
		close(results)
		var states []string
		for p := range results {
			states = append(states, p)
		}
		want := "final_authorized"
		if late {
			want = "cleanup_pending"
		}
		if len(states) != 1 || states[0] != want {
			t.Fatal(states, want)
		}
	}
}
func TestLightDelegationAllowanceAndImmutableTranscript(t *testing.T) {
	l, now, o := delegationFixture(t)
	stageDelegation(t, l, o, "armed")
	if used, err := l.SpentInPeriod(t.Context(), o.VaultID, ""); err != nil || used != 0 {
		t.Fatal(used, err)
	}
	if _, err := l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, "claimed", `{}`, ""}, o.FeeSats-1); !errors.Is(err, ErrPeriodAllowanceExceeded) {
		t.Fatal(err)
	}
	stageDelegation(t, l, o, "nonces_committed")
	if _, err := l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, "nonces_committed", `{"changed":true}`, ""}, 0); err == nil {
		t.Fatal("nonce transcript overwritten")
	}
	stageDelegation(t, l, o, "confirmed")
	if used, err := l.SpentInPeriod(t.Context(), o.VaultID, ""); err != nil || used != o.FeeSats {
		t.Fatal(used, err)
	}
	*now = now.Add(24*time.Hour + time.Second)
	if used, err := l.SpentInPeriod(t.Context(), o.VaultID, ""); err != nil || used != 0 {
		t.Fatal(used, err)
	}
	if _, err := l.ScheduleLightDelegation(t.Context(), o); err != nil {
		t.Fatal("expired exact retry", err)
	}
	o.FeeSats++
	if _, err := l.ScheduleLightDelegation(t.Context(), o); err == nil {
		t.Fatal("changed plan retry")
	}
}
func TestLightDelegationTamperCannotHideOwnership(t *testing.T) {
	for _, query := range []string{
		`UPDATE light_delegation_operation SET vault_id='other'`,
		`UPDATE light_delegation_operation SET payload=replace(payload,'123','0')`,
		`UPDATE light_delegation_event SET phase='cancelled' WHERE phase='claimed'`,
		`UPDATE light_delegation_event SET payload=replace(payload,'claimed','cancelled') WHERE phase='claimed'`,
	} {
		t.Run(query, func(t *testing.T) {
			l, _, o := delegationFixture(t)
			createPolicyTestVault(t, l, "other", 0x62)
			stageDelegation(t, l, o, "register_dispatched")
			if _, err := l.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := l.ListLightDelegations(t.Context()); err == nil {
				t.Fatal("tamper accepted")
			}
			if _, err := l.SpentInPeriod(t.Context(), o.VaultID, ""); err == nil {
				t.Fatal("tamper hid allowance")
			}
		})
	}
}
func TestLightDelegationSchema4MigrationPreservesRows(t *testing.T) {
	path, _, _ := populatedV2Database(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if err := applyConnectorMigration(db, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err := applyRecoveryBackupMigration(db); err != nil {
		t.Fatal(err)
	}
	if err := validateV4Baseline(db, createVaultBoardSchema); err != nil {
		t.Fatal(err)
	}
	before := connectorMigrationRows(t, db)
	count, err := economicOutflowCount(db)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	l, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if !reflect.DeepEqual(before, connectorMigrationRows(t, l.db)) {
		t.Fatal("old rows changed")
	}
	after, err := economicOutflowCount(l.db)
	if err != nil || after != count {
		t.Fatal(after, count, err)
	}
}
func TestLightDelegationRestartRetainsSingleTranscript(t *testing.T) {
	l, now, o := delegationFixture(t)
	stageDelegation(t, l, o, "nonces_committed")
	var path string
	rows, err := l.db.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		var seq int
		var name string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			t.Fatal(err)
		}
	}
	rows.Close()
	if path == "" || !filepath.IsAbs(path) {
		t.Fatal(path)
	}
	l.Close()
	reopened, err := OpenLedger(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, "nonces_committed", `{"peer":"changed"}`, ""}, 0); err == nil {
		t.Fatal("restart reused nonce")
	}
	all, err := reopened.ListLightDelegations(t.Context())
	if err != nil || len(all) != 1 || all[0].State() != "nonces_committed" {
		t.Fatal(all, err)
	}
}

func TestLightDelegationDeletedNonceRecordCannotBeReplacedAtSameSequence(t *testing.T) {
	l, _, o := delegationFixture(t)
	sequence, err := OpenMonotonic(filepath.Join(t.TempDir(), "independent-sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	stageDelegation(t, l, o, "nonces_committed")
	before, exists, err := sequence.read()
	if err != nil || !exists {
		t.Fatal(before, err)
	}
	if _, err := l.db.Exec(`DELETE FROM light_delegation_event WHERE phase='nonces_committed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ListLightDelegations(t.Context()); err == nil {
		t.Fatal("deleted transcript trusted")
	}
	// The new peer transcript would bring the SQL count back to the old value.
	// It must fail on the pre-mutation sequence, before any new signature can use it.
	if _, err := l.AdvanceLightDelegation(t.Context(), LightDelegationEvent{o.OperationID, "nonces_committed", `{"peer":"changed"}`, ""}, 0); err == nil {
		t.Fatal("removed nonce record replaced")
	}
	after, _, err := sequence.read()
	if err != nil || after != before {
		t.Fatal("sequence changed", after, before, err)
	}
}
