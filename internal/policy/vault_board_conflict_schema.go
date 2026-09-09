package policy

import (
	"database/sql"
	"fmt"
)

const createVaultBoardConflictSchema = `CREATE TABLE vault_board_conflict (
 operation_id TEXT NOT NULL,
 attempt INTEGER NOT NULL CHECK (attempt >= 0 AND attempt <= 4294967295),
 phase TEXT NOT NULL CHECK (phase = 'finalize'),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 1048576),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
 PRIMARY KEY (operation_id, attempt),
 FOREIGN KEY (operation_id, attempt, phase) REFERENCES vault_board_authorization(operation_id, attempt, phase)
)`

func applyVaultBoardConflictMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(createVaultBoardConflictSchema); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE schema_meta SET version=9 WHERE version=8`)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("boarding conflict recovery requires schema 8")
	}
	return tx.Commit()
}

func validateVaultBoardConflictSchema(db *sql.DB) error {
	var actual string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='vault_board_conflict'`).Scan(&actual); err != nil {
		return err
	}
	if normalizeCheck(actual) != normalizeCheck(createVaultBoardConflictSchema) {
		return fmt.Errorf("boarding conflict schema changed")
	}
	return nil
}
