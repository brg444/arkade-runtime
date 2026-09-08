package policy

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
)

func rollingV5Database(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v5.sqlite")
	l, err := OpenLedger(path, defaultRenewalTestClock)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, l, "existing-opaque-vault", 0x71)
	for _, statement := range []string{
		`DROP TABLE rolling_event`, `DROP TABLE rolling_operation`, `DROP TABLE rolling_enrollment`, `UPDATE schema_meta SET version=5`,
	} {
		if _, err = l.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return l.db, path
}

func TestRollingSchemaMigrationPreservesV5IdentityAndSequence(t *testing.T) {
	db, path := rollingV5Database(t)
	var before []byte
	if err := db.QueryRow(`SELECT integrity_mac FROM vault WHERE vault_id='existing-opaque-vault'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := OpenLedger(path, defaultRenewalTestClock)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if err = current.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	v, c, err := current.LoadVerifiedVault("existing-opaque-vault", testIntegrityKey())
	if err != nil || v == nil || c == nil || !bytes.Equal(v.IntegrityMAC, before) {
		t.Fatal("migration changed enrolled identity", err)
	}
	if version, err := current.SchemaVersion(); err != nil || version != 6 {
		t.Fatal("migration version", version, err)
	}
	if count, err := economicOutflowCount(current.db); err != nil || count != 0 {
		t.Fatal("migration changed economic sequence", count, err)
	}
}

func TestRollingMigrationRejectsV5DriftBeforeAnyWrite(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE recovery_backup ADD COLUMN unexpected TEXT`,
		`DROP TABLE light_delegation_event`,
		`CREATE TABLE rolling_event (unexpected TEXT)`,
		`CREATE TRIGGER erase_credential AFTER INSERT ON schema_meta BEGIN DELETE FROM vault_credential; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			db, path := rollingV5Database(t)
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if l, err := OpenLedger(path, nil); err == nil {
				l.Close()
				t.Fatal("drifted v5 migrated")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			if err = db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || version != 5 {
				t.Fatal("failed migration changed version", version, err)
			}
			if hasTable(db, "rolling_enrollment") || hasTable(db, "rolling_operation") {
				t.Fatal("partial migration survived")
			}
		})
	}
}

func TestRollingSchemaRejectsDriftOnRestart(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE rolling_event ADD COLUMN unexpected TEXT`,
		`DROP TABLE rolling_event`,
		`CREATE INDEX hide_rolling ON rolling_operation(vault_id)`,
		`CREATE TRIGGER erase_rolling AFTER INSERT ON rolling_event BEGIN DELETE FROM rolling_operation; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "current.sqlite")
			l, err := OpenLedger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			l.Close()
			if l, err := OpenLedger(path, nil); err == nil {
				l.Close()
				t.Fatal("rolling schema drift accepted")
			}
		})
	}
}
