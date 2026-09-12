package policy

import (
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

func validateVaultBoardConflictSchema(db schemaQuerier) error {
	var actual string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='vault_board_conflict'`).Scan(&actual); err != nil {
		return err
	}
	if normalizeCheck(actual) != normalizeCheck(createVaultBoardConflictSchema) {
		return fmt.Errorf("boarding conflict schema changed")
	}
	return nil
}
