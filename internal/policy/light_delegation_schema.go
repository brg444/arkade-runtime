package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

const createLightDelegationSchema = `
CREATE TABLE light_delegation_operation (
 operation_id TEXT PRIMARY KEY,
 vault_id TEXT NOT NULL REFERENCES vault(vault_id),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 131072),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE light_delegation_event (
 operation_id TEXT NOT NULL REFERENCES light_delegation_operation(operation_id),
 phase TEXT NOT NULL,
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 8000000),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
 PRIMARY KEY (operation_id,phase)
);
`

func applyLightDelegationMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(createLightDelegationSchema); err != nil {
		return err
	}
	r, err := tx.Exec(`UPDATE schema_meta SET version=5 WHERE version=4`)
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("delegation requires schema 4")
	}
	return tx.Commit()
}
func validateLightDelegationSchema(db *sql.DB) error {
	for _, statement := range strings.Split(strings.TrimSpace(createLightDelegationSchema), ";") {
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
			return fmt.Errorf("Light delegation schema changed")
		}
	}
	return nil
}
