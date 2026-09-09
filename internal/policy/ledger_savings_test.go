package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

func ledgerSavingsPolicyFixture(t *testing.T) (*Ledger, LedgerSavingsEnrollment) {
	t.Helper()
	raw, err := os.ReadFile("../vault/savings/testdata/ledger-key-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Input savings.LedgerSavingsKeyContext `json:"input"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	input := vectors[0].Input
	contextJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	rec := LedgerSavingsEnrollment{VaultID: input.VaultID, ContextJSON: contextJSON, DescriptorHash: strings.Repeat("12", 32)}
	if err := SealLedgerSavingsEnrollment(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	l := openPolicyTestLedger(t, nil)
	token := bytes.Repeat([]byte{91}, 32)
	now := l.NowUTC()
	if err := l.PutInvite(token, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	create := policyTestVaultInput(t, rec.VaultID, 91, token)
	create.Record.TemplateVersion = savings.LedgerNativeTemplate
	if err := SealVaultRecord(&create.Record, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	create.LedgerSavings = &rec
	if err := l.CreateVault(create); err != nil {
		t.Fatal(err)
	}
	return l, rec
}
func ledgerSavingsRecoveryFixture(id string) LedgerSavingsRecovery {
	return LedgerSavingsRecovery{RecoverySession: RecoverySession{VaultID: id, Purpose: "initiate", InputTxid: strings.Repeat("ab", 32), InputVout: 0, DestScript: strings.Repeat("cd", 34), LastSighash: strings.Repeat("ef", 32)}, CandidatePSBT: "retained canonical candidate"}
}
func TestLedgerSavingsEnrollmentMACBeforeContextUse(t *testing.T) {
	for _, column := range []string{"context_json", "descriptor_hash"} {
		t.Run(column, func(t *testing.T) {
			l, rec := ledgerSavingsPolicyFixture(t)
			if _, err := l.GetLedgerSavingsEnrollment(rec.VaultID); err != nil {
				t.Fatal(err)
			}
			value := []byte(strings.Repeat("34", 32))
			if column == "context_json" {
				value = []byte(`{"templateVersion":"attacker"}`)
			}
			if _, err := l.db.Exec(`UPDATE ledger_savings_enrollment SET `+column+`=? WHERE vault_id=?`, value, rec.VaultID); err != nil {
				t.Fatal(err)
			}
			if _, err := l.GetLedgerSavingsEnrollment(rec.VaultID); err == nil || !strings.Contains(err.Error(), "MAC mismatch") {
				t.Fatal("tampered context was decoded or trusted before MAC", err)
			}
		})
	}
}
func TestLedgerSavingsRecoveryJournalSequenceAndReplay(t *testing.T) {
	l, rec := ledgerSavingsPolicyFixture(t)
	monotonic, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(monotonic); err != nil {
		t.Fatal(err)
	}
	next := ledgerSavingsRecoveryFixture(rec.VaultID)
	action, pending, err := l.ApplyLedgerSavingsRecovery(next)
	if err != nil || action != ReplaySign {
		t.Fatal("reserve", action, err)
	}
	count, _, err := monotonic.read()
	if err != nil || count != 1 {
		t.Fatal("reservation did not advance sequence", count, err)
	}
	_, retry, err := l.ApplyLedgerSavingsRecovery(next)
	if err != nil || retry.CandidatePSBT != pending.CandidatePSBT {
		t.Fatal("retry changed candidate", err)
	}
	complete := *pending
	complete.Signature = []byte("signed canonical candidate")
	_, signed, err := l.ApplyLedgerSavingsRecovery(complete)
	if err != nil {
		t.Fatal(err)
	}
	count, _, err = monotonic.read()
	if err != nil || count != 2 {
		t.Fatal("completion did not advance sequence", count, err)
	}
	action, replayed, err := l.ApplyLedgerSavingsRecovery(next)
	if err != nil || action != ReplayReplay || !bytes.Equal(replayed.Signature, signed.Signature) {
		t.Fatal("completed result not replayed", err)
	}
	replacement := next
	replacement.LastSighash = strings.Repeat("ac", 32)
	replacement.CandidatePSBT = "canonical replacement"
	_, pending, err = l.ApplyLedgerSavingsRecovery(replacement)
	if err != nil || len(pending.Signature) != 0 {
		t.Fatal("replacement carried stale signature", err)
	}
	if _, _, err := l.ApplyLedgerSavingsRecovery(complete); err == nil {
		t.Fatal("late completion overwrote replacement")
	}
	count, _, err = monotonic.read()
	if err != nil || count != 3 {
		t.Fatal("replacement sequence", count, err)
	}
	if _, err := l.db.Exec(`DELETE FROM ledger_savings_recovery_event WHERE event_id=3`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.ApplyLedgerSavingsRecovery(replacement); err == nil {
		t.Fatal("database rollback was repaired by issuing new authority")
	}
}
func TestLedgerSavingsRecoveryJournalAuthenticatesBeforeFiltering(t *testing.T) {
	l, rec := ledgerSavingsPolicyFixture(t)
	next := ledgerSavingsRecoveryFixture(rec.VaultID)
	if _, _, err := l.ApplyLedgerSavingsRecovery(next); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := l.db.QueryRow(`SELECT record FROM ledger_savings_recovery_event WHERE event_id=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var event LedgerSavingsRecovery
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	event.InputTxid = strings.Repeat("11", 32)
	changed, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`UPDATE ledger_savings_recovery_event SET record=? WHERE event_id=1`, changed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.ApplyLedgerSavingsRecovery(next); err == nil || !strings.Contains(err.Error(), "MAC mismatch") {
		t.Fatal("hidden conflict was trusted", err)
	}
}
func TestLedgerSavingsMigrationPreservesVersionNineRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration.sqlite")
	l, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, l, "legacy-vault", 92)
	before, _, err := l.LoadVerifiedVault("legacy-vault", testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`DROP TABLE ledger_savings_recovery_event`, `DROP TABLE ledger_savings_enrollment`, `UPDATE schema_meta SET version=9`} {
		if _, err := l.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if err := migrated.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	after, _, err := migrated.LoadVerifiedVault("legacy-vault", testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.IntegrityMAC, after.IntegrityMAC) || VaultRecordsCanonicallyEqual(*before, *after) != nil {
		t.Fatal("legacy vault changed during additive migration")
	}
	if version, err := migrated.SchemaVersion(); err != nil || version != 10 {
		t.Fatal("migration version", version, err)
	}
}

func TestLedgerSavingsRecoveryCompletionMustMatchReservation(t *testing.T) {
	l, rec := ledgerSavingsPolicyFixture(t)
	next := ledgerSavingsRecoveryFixture(rec.VaultID)
	premature := next
	premature.Signature = []byte("not reserved")
	if _, _, err := l.ApplyLedgerSavingsRecovery(premature); err == nil {
		t.Fatal("unreserved completion accepted")
	}
	_, pending, err := l.ApplyLedgerSavingsRecovery(next)
	if err != nil {
		t.Fatal(err)
	}
	changed := *pending
	changed.CandidatePSBT = "changed canonical candidate"
	changed.Signature = []byte("signed changed candidate")
	if _, _, err := l.ApplyLedgerSavingsRecovery(changed); err == nil {
		t.Fatal("changed completion accepted")
	}
	changed = *pending
	changed.DirectProof = bytes.Repeat([]byte{1}, 64)
	changed.Signature = []byte("signed changed proof")
	if _, _, err := l.ApplyLedgerSavingsRecovery(changed); err == nil {
		t.Fatal("changed proof completion accepted")
	}
}
func TestLedgerSavingsRecoverySequenceWriteFailureRetainsReservation(t *testing.T) {
	l, rec := ledgerSavingsPolicyFixture(t)
	path := filepath.Join(t.TempDir(), "sequence")
	monotonic, err := OpenMonotonic(path, testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(monotonic); err != nil {
		t.Fatal(err)
	}
	// Existing count0 remains readable, but the atomic replacement write fails.
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	next := ledgerSavingsRecoveryFixture(rec.VaultID)
	if _, _, err := l.ApplyLedgerSavingsRecovery(next); err == nil {
		t.Fatal("sequence write failure ignored")
	}
	var events int
	if err := l.db.QueryRow(`SELECT count(*) FROM ledger_savings_recovery_event`).Scan(&events); err != nil || events != 1 {
		t.Fatal(events, err)
	}
	count, _, err := monotonic.read()
	if err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	_, resumed, err := l.ApplyLedgerSavingsRecovery(next)
	if err != nil || resumed.CandidatePSBT != next.CandidatePSBT {
		t.Fatal("exact retry failed", err)
	}
	count, _, err = monotonic.read()
	if err != nil || count != 1 {
		t.Fatal("retry did not synchronize sequence", count, err)
	}
}
func TestLedgerSavingsConcurrentRecoveryReservesOneCandidate(t *testing.T) {
	l, rec := ledgerSavingsPolicyFixture(t)
	first := ledgerSavingsRecoveryFixture(rec.VaultID)
	second := first
	second.LastSighash = strings.Repeat("ac", 32)
	second.CandidatePSBT = "competing canonical candidate"
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, next := range []LedgerSavingsRecovery{first, second} {
		wg.Go(func() { _, _, err := l.ApplyLedgerSavingsRecovery(next); results <- err })
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("conflicting reservations", accepted)
	}
	var events int
	if err := l.db.QueryRow(`SELECT count(*) FROM ledger_savings_recovery_event`).Scan(&events); err != nil || events != 1 {
		t.Fatal(events, err)
	}
}
func TestLedgerSavingsEnrollmentSidecarFailureRollsBackAtomicCreate(t *testing.T) {
	l, rec := ledgerSavingsPolicyFixture(t)
	token := bytes.Repeat([]byte{94}, 32)
	now := l.NowUTC()
	if err := l.PutInvite(token, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	create := policyTestVaultInput(t, "another-ledger-vault", 94, token)
	create.Record.TemplateVersion = savings.LedgerNativeTemplate
	if err := SealVaultRecord(&create.Record, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	create.LedgerSavings = &rec // Existing immutable sidecar belongs to another vault.
	if err := l.CreateVault(create); err == nil {
		t.Fatal("mismatched sidecar accepted")
	}
	var vaults int
	if err := l.db.QueryRow(`SELECT count(*) FROM vault WHERE vault_id=?`, create.Record.VaultID).Scan(&vaults); err != nil || vaults != 0 {
		t.Fatal("partial vault survived", vaults, err)
	}
}
