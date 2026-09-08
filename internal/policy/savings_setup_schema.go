package policy

import (
	"database/sql"
	"fmt"
)

func applySavingsSetupMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE schema_meta SET version=6 WHERE version=5`)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("Savings setup requires schema 5")
	}
	return tx.Commit()
}
