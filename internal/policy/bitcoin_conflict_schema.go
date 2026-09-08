package policy

import (
	"database/sql"
	"fmt"
)

// Version 8 fences the new, evidence-bound post-dispatch release semantics.
// Tables, authenticated rows, and the independent sequence stay unchanged.
func applyBitcoinConflictMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE schema_meta SET version=8 WHERE version=7`)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("Bitcoin conflict recovery requires schema 7")
	}
	return tx.Commit()
}
