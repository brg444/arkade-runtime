package policy

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// Opt-in qualification against a SQLite backup of the deployed database.
// The supplied backup is read only; migration runs on a disposable copy.
// No signing key is required and no wallet rows are logged.
func TestDeployedEnrollmentMigrationSnapshot(t *testing.T) {
	source := os.Getenv("VAULT_MIGRATION_SNAPSHOT")
	if source == "" {
		t.Skip("set VAULT_MIGRATION_SNAPSHOT to a consistent SQLite backup")
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "migration.sqlite")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || (version != 9 && version != 10) {
		t.Fatal("expected deployed schema9 or schema10", err)
	}
	before := migrationFingerprints(t, db)
	count, err := economicOutflowCount(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedgerForNetwork(path, nil, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if version, err := ledger.SchemaVersion(); err != nil || version != schemaVersion {
		t.Fatal("expected current schema", err)
	}
	after := migrationFingerprints(t, ledger.db)
	for name, expected := range before {
		if name != "vault" && name != "pending_enrollment" && after[name] != expected {
			t.Fatalf("migration changed pre-existing table %s", name)
		}
	}
	expectedAdded := 0
	if version == 9 {
		expectedAdded = 4
	}
	if len(after) != len(before)+expectedAdded {
		t.Fatal("unexpected table additions")
	}
	for _, table := range []string{"ledger_savings_enrollment", "ledger_savings_recovery_event"} {
		if version != 9 {
			continue
		}
		var rows int
		if err := ledger.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&rows); err != nil || rows != 0 {
			t.Fatal("new table is not empty", err)
		}
	}
	if got, err := economicOutflowCount(ledger.db); err != nil || got != count {
		t.Fatal("economic sequence changed", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = OpenLedgerForNetwork(path, nil, "mainnet")
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer ledger.Close()
	if !reflect.DeepEqual(after, migrationFingerprints(t, ledger.db)) {
		t.Fatal("reopen changed tables")
	}
	t.Logf("deployed schema%d backup migrates to the current schema; authenticated rows and economic count preserved; reopen succeeds", version)
}

func migrationFingerprints(t *testing.T, db *sql.DB) map[string][32]byte {
	t.Helper()
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	ddl := map[string]string{}
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			t.Fatal(err)
		}
		ddl[name] = statement
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	result := map[string][32]byte{}
	for name, statement := range ddl {
		// Names have been returned by SQLite, quote them as identifiers.
		quoted := `"`
		for _, ch := range name {
			if ch == '"' {
				quoted += `""`
			} else {
				quoted += string(ch)
			}
		}
		quoted += `"`
		r, err := db.Query(`SELECT * FROM ` + quoted)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := r.Columns()
		if err != nil {
			t.Fatal(err)
		}
		records := []string{}
		for r.Next() {
			values := make([]any, len(cols))
			refs := make([]any, len(cols))
			for i := range values {
				refs[i] = &values[i]
			}
			if err := r.Scan(refs...); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, string(encoded))
		}
		if err := r.Err(); err != nil {
			t.Fatal(err)
		}
		r.Close()
		sort.Strings(records)
		encoded, err := json.Marshal([]any{statement, cols, records})
		if err != nil {
			t.Fatal(err)
		}
		result[name] = sha256.Sum256(encoded)
		rowBytes, err := json.Marshal([]any{cols, records})
		if err != nil {
			t.Fatal(err)
		}
		result[name+":rows"] = sha256.Sum256(rowBytes)
	}
	return result
}

func TestSchemaNineMigrationRejectsUnrecognizedBaselineBeforeWriting(t *testing.T) {
	for _, scenario := range []string{"altered-boarding", "unreleased-ledger-nine"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.sqlite")
			l, err := OpenLedger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			statements := `UPDATE schema_meta SET version=9;`
			if scenario == "altered-boarding" {
				statements += `DROP TABLE ledger_savings_recovery_event; DROP TABLE ledger_savings_enrollment; ALTER TABLE vault_board_conflict ADD COLUMN unexpected TEXT;`
			} else {
				statements += `DROP TABLE vault_board_conflict;`
			}
			if _, err := l.db.Exec(statements); err != nil {
				t.Fatal(err)
			}
			before := migrationFingerprints(t, l.db)
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			if unexpected, err := OpenLedger(path, nil); err == nil {
				unexpected.Close()
				t.Fatal("unrecognized baseline accepted")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			if err := db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || (version != 9 && version != 10) {
				t.Fatal("failed migration changed version", err)
			}
			if !reflect.DeepEqual(before, migrationFingerprints(t, db)) {
				t.Fatal("failed migration changed tables")
			}
		})
	}
}

func TestDeployedEnrollmentMigrationSnapshotFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.sqlite")
	l, err := OpenLedgerForNetwork(path, nil, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	restoreSchemaTenConstraints(t, l)
	if _, err := l.db.Exec(`DROP TABLE ledger_savings_recovery_event; DROP TABLE ledger_savings_enrollment; UPDATE schema_meta SET version=9`); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_MIGRATION_SNAPSHOT", path)
	TestDeployedEnrollmentMigrationSnapshot(t)
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("source backup changed", err)
	}
}
