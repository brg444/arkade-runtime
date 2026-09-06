package policy

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecoveryBackupCASIntegrityAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.sqlite")
	l, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := testIntegrityKey()
	if err = l.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	createPolicyTestVault(t, l, id, 0x51)
	first, err := l.PutRecoveryBackup(id, 0, "encrypted-one")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := l.PutRecoveryBackup(id, 0, "encrypted-one")
	if err != nil || retry.Revision != first.Revision {
		t.Fatal("lost response was not idempotent", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, payload := range []string{"encrypted-two", "encrypted-three"} {
		wg.Add(1)
		go func(p string) { defer wg.Done(); _, err := l.PutRecoveryBackup(id, 1, p); results <- err }(payload)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent writers both won")
	}
	if _, err = l.PutRecoveryBackup(id, 2, strings.Repeat("x", MaxRecoveryBackupBytes+1)); err == nil {
		t.Fatal("oversized backup")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = l.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	saved, err := l.GetRecoveryBackup(id)
	if err != nil || saved.Revision != 2 {
		t.Fatal("backup did not persist", err)
	}
	if _, err = l.db.Exec(`UPDATE recovery_backup SET payload='tampered' WHERE vault_id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = l.GetRecoveryBackup(id); err == nil {
		t.Fatal("tampered read")
	}
	if _, err = l.PutRecoveryBackup(id, 2, "overwrite"); err == nil {
		t.Fatal("tampered row overwritten")
	}
}

func TestRecoveryBackupMigrationPreservesSchemaTwoRecordsAndSequence(t *testing.T) {
	db, path := legacyRenewalDatabase(t)
	if _, err := db.Exec(createLightRenewalSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE schema_meta SET version=2`); err != nil {
		t.Fatal(err)
	}
	old := &Ledger{db: db, clock: defaultRenewalTestClock, network: "mutinynet"}
	if err := old.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	createPolicyTestVault(t, old, id, 0x51)
	sequencePath := filepath.Join(t.TempDir(), "policy-sequence")
	sequence, err := OpenMonotonic(sequencePath, testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := old.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	op := LightRenewalOperation{OperationID: strings.Repeat("01", 16), VaultID: id, InputTxid: strings.Repeat("02", 32), FeeSats: 123, PlanDigest: strings.Repeat("03", 32), Plan: `{"renewal":true}`, ExpiresAt: defaultRenewalTestClock().Add(5 * time.Minute).Format(time.RFC3339)}
	if _, err := old.ReserveLightRenewal(context.Background(), op, 123); err != nil {
		t.Fatal(err)
	}
	appendRenewal(t, old, op, "register_authorized")
	snapshot := func(db *sql.DB) []byte {
		var result []byte
		for _, query := range []string{
			`SELECT integrity_mac FROM vault WHERE vault_id='` + id + `'`,
			`SELECT integrity_mac FROM light_renewal_operation WHERE operation_id='` + op.OperationID + `'`,
			`SELECT integrity_mac FROM light_renewal_event WHERE operation_id='` + op.OperationID + `'`,
		} {
			var mac []byte
			if err := db.QueryRow(query).Scan(&mac); err != nil {
				t.Fatal(err)
			}
			result = append(result, mac...)
		}
		return result
	}
	before := snapshot(db)
	sequenceBefore, err := os.ReadFile(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenLedger(path, defaultRenewalTestClock)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if err := migrated.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := migrated.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, snapshot(migrated.db)) {
		t.Fatal("migration changed authenticated records")
	}
	if version, err := migrated.SchemaVersion(); err != nil || version != recoveryBackupSchemaVersion {
		t.Fatal("schema did not migrate", err)
	}
	if _, err := migrated.PutRecoveryBackup(id, 0, "opaque-encrypted-backup"); err != nil {
		t.Fatal(err)
	}
	if n, err := economicOutflowCount(migrated.db); err != nil || n != 2 {
		t.Fatal("backup changed economic sequence", n, err)
	}
	sequenceAfter, err := os.ReadFile(sequencePath)
	if err != nil || !bytes.Equal(sequenceBefore, sequenceAfter) {
		t.Fatal("backup changed independent sequence", err)
	}
}

func TestRecoveryBackupMigrationRejectsSchemaTwoDriftBeforeWriting(t *testing.T) {
	db, path := legacyRenewalDatabase(t)
	if _, err := db.Exec(createLightRenewalSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE schema_meta SET version=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE light_renewal_event ADD COLUMN junk TEXT`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if accepted, err := OpenLedger(path, nil); err == nil {
		accepted.Close()
		t.Fatal("tampered prior schema migrated")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || version != 2 {
		t.Fatal("refused migration changed version", err)
	}
	if hasTable(db, "recovery_backup") {
		t.Fatal("refused migration created backup table")
	}
}
