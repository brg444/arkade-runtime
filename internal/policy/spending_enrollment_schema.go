package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

// The historical DDL remains the source baseline for verified upgrades. Only
// the tier constraints change; columns, stored bytes and MAC domains are preserved.
func sharedSpendingTenantSchema() string {
	ddl := strings.ReplaceAll(createMultiTenantSchema, "protection_tier IN ('standard', 'advanced')", "protection_tier IN ('light', 'standard', 'advanced')")
	return strings.Replace(ddl, "(protection_tier = 'standard' AND recovery_key_compressed IS NULL)", "(protection_tier IN ('light', 'standard') AND recovery_key_compressed IS NULL)", 1)
}

func applySpendingEnrollmentMigration(db *sql.DB) (err error) {
	// This runs before the Ledger is published and while it owns one connection.
	// SQLite's table-rebuild procedure requires foreign keys disabled outside the transaction.
	if _, err = db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	defer func() {
		_, restoreErr := db.Exec(`PRAGMA foreign_keys = ON`)
		if err == nil {
			err = restoreErr
		}
	}()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = rebuildEnrollmentTables(tx, sharedSpendingTenantSchema()); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE schema_meta SET version=11 WHERE version=10`)
	if err != nil {
		return err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return fmt.Errorf("Spending enrollment requires schema10")
	}
	if err = validateMultiTenantSchemaOn(tx); err != nil {
		return err
	}
	if err = requireForeignKeyCheckClean(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func rebuildEnrollmentTables(tx *sql.Tx, ddl string) error {
	for _, table := range []string{"vault", "pending_enrollment"} {
		var definition string
		for _, stmt := range strings.Split(ddl, ";") {
			if strings.HasPrefix(strings.TrimSpace(stmt), "CREATE TABLE IF NOT EXISTS "+table+" (") {
				definition = strings.TrimSpace(stmt)
				break
			}
		}
		if definition == "" {
			return fmt.Errorf("Spending enrollment schema missing %s", table)
		}
		temporary := table + "_spending_upgrade"
		definition = strings.Replace(definition, "CREATE TABLE IF NOT EXISTS "+table+" (", "CREATE TABLE "+temporary+" (", 1)
		for _, statement := range []string{definition, "INSERT INTO " + temporary + " SELECT * FROM " + table, "DROP TABLE " + table, "ALTER TABLE " + temporary + " RENAME TO " + table} {
			if _, err := tx.Exec(statement); err != nil {
				return err
			}
		}
	}
	return nil
}
