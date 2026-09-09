package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

const createLedgerSavingsSchema = `
CREATE TABLE ledger_savings_enrollment (
 vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
 context_json BLOB NOT NULL CHECK(length(context_json)>0 AND length(context_json)<=8192),
 descriptor_hash TEXT NOT NULL CHECK(length(descriptor_hash)=64),
 integrity_mac BLOB NOT NULL CHECK(length(integrity_mac)=32)
);
CREATE TABLE ledger_savings_recovery_event (
 event_id INTEGER PRIMARY KEY CHECK(event_id>0),
 vault_id TEXT NOT NULL REFERENCES ledger_savings_enrollment(vault_id),
 record BLOB NOT NULL CHECK(length(record)>0 AND length(record)<=393216),
 integrity_mac BLOB NOT NULL CHECK(length(integrity_mac)=32)
);
`

func applyLedgerSavingsMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(createLedgerSavingsSchema); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE schema_meta SET version=10 WHERE version=9`)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("Ledger Savings requires schema9")
	}
	return tx.Commit()
}
func validateLedgerSavingsSchema(db *sql.DB) error {
	for _, statement := range strings.Split(strings.TrimSpace(createLedgerSavingsSchema), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		name := strings.Fields(statement)[2]
		var actual string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&actual); err != nil {
			return err
		}
		if normalizeCheck(actual) != normalizeCheck(statement) {
			return fmt.Errorf("Ledger Savings table %s changed", name)
		}
	}
	return nil
}
