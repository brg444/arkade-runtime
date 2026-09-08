package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

const createRollingSchema = `
CREATE TABLE rolling_enrollment (
 vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
 controller_id TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 16384),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE rolling_operation (
 operation_id TEXT PRIMARY KEY,
 vault_id TEXT NOT NULL REFERENCES rolling_enrollment(vault_id),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 2000000),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE rolling_event (
 operation_id TEXT NOT NULL REFERENCES rolling_operation(operation_id),
 phase TEXT NOT NULL,
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 8000000),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
 PRIMARY KEY (operation_id,phase)
);
`

func applyRollingMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(createRollingSchema); err != nil {
		return err
	}
	r, err := tx.Exec(`UPDATE schema_meta SET version=7 WHERE version=6`)
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("rolling allowance requires schema 6")
	}
	return tx.Commit()
}
func validateRollingSchema(db *sql.DB) error {
	for _, statement := range strings.Split(strings.TrimSpace(createRollingSchema), ";") {
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
			return fmt.Errorf("rolling allowance schema changed")
		}
	}
	return nil
}
