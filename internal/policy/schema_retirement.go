package policy

import (
	"context"
	"database/sql"
	"fmt"
	"math"
)

// Called under the ledger mutex before the integrity key is published. Schema
// retirement is atomic, and the external sequence retains its bytes and domain.
func (l *Ledger) initializeIntegrityState(key []byte) error {
	if l.db == nil {
		return fmt.Errorf("ledger database required")
	}
	boardSchema, err := vaultBoardSchemaForNetwork(l.network)
	if err != nil {
		return err
	}
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	version, rows, err := schemaMetaState(tx)
	if err != nil || rows != 1 {
		return fmt.Errorf("invalid schema metadata")
	}
	if err := validateRetainedSchema(tx, boardSchema, version); err != nil {
		return err
	}
	if version == previousSchemaVersion {
		if err := l.retireSchemaEleven(tx, key); err != nil {
			return err
		}
	} else {
		_, present, err := readPolicySequenceBase(tx, l.network, key)
		if err != nil {
			return err
		}
		if !present {
			// A fresh schema can be reopened before its first key installation.
			// An enrolled database never acquires a replacement sequence base.
			var vaults int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&vaults); err != nil {
				return err
			}
			count, err := economicOutflowCount(tx)
			if err != nil {
				return err
			}
			if vaults != 0 || count != 0 {
				return fmt.Errorf("policy sequence base missing for enrolled database")
			}
			if err := l.insertPolicySequenceBase(tx, 0, key); err != nil {
				return err
			}
		}
	}
	if err := validateRetainedSchema(tx, boardSchema, schemaVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func (l *Ledger) insertPolicySequenceBase(tx *sql.Tx, base uint64, key []byte) error {
	if base > math.MaxInt64 {
		return fmt.Errorf("policy sequence base overflow")
	}
	_, err := tx.Exec(`INSERT INTO policy_sequence_base(id,base,integrity_mac) VALUES(1,?,?)`, int64(base), policySequenceBaseMAC(l.network, base, key))
	return err
}

func (l *Ledger) retireSchemaEleven(tx *sql.Tx, key []byte) error {
	// Authenticate every descriptor before using its template to select rows
	// for removal. SQL never filters on an unauthenticated program identifier.
	rows, err := tx.Query(`SELECT vault_id FROM vault ORDER BY vault_id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var retired []string
	for _, id := range ids {
		record, credential, err := loadVault(tx, id)
		if err != nil {
			return err
		}
		if record == nil {
			return fmt.Errorf("retirement enrollment missing")
		}
		if err := verifyVaultRecord(record, key); err != nil {
			return err
		}
		if credential != nil {
			if err := verifyVaultCredential(credential, key); err != nil {
				return err
			}
		}
		switch record.TemplateVersion {
		case "phone-connector-recovery-savings-v1", "phone-connector-recovery-savings-v2", "vaulted-light-v1":
			retired = append(retired, id)
		}
	}
	if err := verifyRetirementOwnership(tx, key); err != nil {
		return err
	}
	before, err := economicOutflowCount(tx)
	if err != nil {
		return err
	}
	var removedOperations uint64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM connector_operation`).Scan(&removedOperations); err != nil {
		return err
	}
	if removedOperations > math.MaxUint64-before {
		return fmt.Errorf("retirement sequence overflow")
	}
	before += removedOperations
	for _, statement := range []string{`DROP TABLE connector_operation`, `DROP TABLE connector_enrollment`, createPolicySequenceBaseSchema} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	for _, id := range retired {
		if err := deleteRetiredAccount(tx, id); err != nil {
			return err
		}
	}
	after, err := economicOutflowCount(tx)
	if err != nil {
		return err
	}
	if after > before {
		return fmt.Errorf("retirement increased economic rows")
	}
	if err := l.insertPolicySequenceBase(tx, before-after, key); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE schema_meta SET version=? WHERE version=?`, schemaVersion, previousSchemaVersion)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("retirement requires schema 11")
	}
	return nil
}

// Each statement names a fixed ownership edge, in child-before-parent order.
// Current account rows and their existing MACs are never rewritten.
func deleteRetiredAccount(tx *sql.Tx, id string) error {
	for _, statement := range []string{
		`DELETE FROM light_delegation_event WHERE operation_id IN (SELECT operation_id FROM light_delegation_operation WHERE vault_id=?)`,
		`DELETE FROM light_delegation_operation WHERE vault_id=?`,
		`DELETE FROM light_renewal_event WHERE operation_id IN (SELECT operation_id FROM light_renewal_operation WHERE vault_id=?)`,
		`DELETE FROM light_renewal_operation WHERE vault_id=?`,
		`DELETE FROM vtxo_operation_input WHERE operation_id IN (SELECT operation_id FROM vtxo_operation WHERE vault_id=?)`,
		`DELETE FROM vtxo_operation WHERE vault_id=?`,
		`DELETE FROM vault_board_submission WHERE operation_id IN (SELECT operation_id FROM vault_board_operation WHERE vault_id=?)`,
		`DELETE FROM vault_board_dispatch WHERE operation_id IN (SELECT operation_id FROM vault_board_operation WHERE vault_id=?)`,
		`DELETE FROM vault_board_conflict WHERE operation_id IN (SELECT operation_id FROM vault_board_operation WHERE vault_id=?)`,
		`DELETE FROM vault_board_authorization WHERE operation_id IN (SELECT operation_id FROM vault_board_operation WHERE vault_id=?)`,
		`DELETE FROM vault_board_operation WHERE vault_id=?`,
		`DELETE FROM vault_board_enrollment WHERE vault_id=?`,
		`DELETE FROM ledger_savings_recovery_event WHERE vault_id=?`,
		`DELETE FROM ledger_savings_enrollment WHERE vault_id=?`,
		`DELETE FROM recovery_session WHERE vault_id=?`,
		`DELETE FROM recovery_backup WHERE vault_id=?`,
		`DELETE FROM webauthn_sign_count WHERE vault_id=?`,
		`DELETE FROM vault_map WHERE vault_id=?`,
		`DELETE FROM vault_envelope WHERE vault_id=?`,
		`DELETE FROM vault_credential WHERE vault_id=?`,
		`DELETE FROM pending_enrollment WHERE vault_id=?`,
		`DELETE FROM pending_enrollment WHERE token_hash IN (SELECT token_hash FROM invite WHERE consumed_vault_id=?)`,
		`DELETE FROM invite WHERE consumed_vault_id=?`,
		`DELETE FROM vault WHERE vault_id=?`,
	} {
		if _, err := tx.ExecContext(context.Background(), statement, id); err != nil {
			return err
		}
	}
	return nil
}
