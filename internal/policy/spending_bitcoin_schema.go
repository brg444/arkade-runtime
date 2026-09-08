package policy

import (
	"database/sql"
	"fmt"
)

// The physical schema and existing authenticated rows are unchanged. Version 7
// fences readers that only understand fixed-value signer funding.
func applySpendingBitcoinMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE schema_meta SET version=7 WHERE version=6`)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("Bitcoin payments require schema 6")
	}
	return tx.Commit()
}
