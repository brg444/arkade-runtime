package policy

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMainnetLedgerCreatesAndReopensOnlyTheCurrentBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.sqlite")
	ledger, err := OpenMainnetLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasTable(ledger.db, "credential") || hasTable(ledger.db, "credential_envelope") {
		t.Fatal("fresh baseline created singleton compatibility tables")
	}
	if got, err := ledger.SchemaVersion(); err != nil || got != mainnetSchemaVersion {
		t.Fatalf("schema version = %d, %v", got, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenMainnetLedger(path, nil); err != nil {
		t.Fatal(err)
	} else if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMainnetLedgerRefusesLegacyOrUnknownFilesWithoutChangingThem(t *testing.T) {
	for _, schema := range []string{
		`CREATE TABLE credential (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE unrelated (value TEXT)`,
	} {
		path := filepath.Join(t.TempDir(), "old.sqlite")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(schema); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()

		_, err = OpenMainnetLedger(path, nil)
		if err == nil || !strings.Contains(err.Error(), "not the mainnet v2 baseline") {
			t.Fatalf("OpenMainnetLedger error = %v", err)
		}
		db, err = sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if count != 1 {
			t.Fatalf("refused database was changed; table count = %d", count)
		}
	}
}
